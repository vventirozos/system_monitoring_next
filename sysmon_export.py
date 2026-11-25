#!/usr/bin/env python3
"""sysmon_export - read system_monitoring_next logs and export them.

  sysmon_export.py -l LOGDIR list
  sysmon_export.py -l LOGDIR export TARGET CHECK [--last 2h] [-f csv|tsv|json|table]
  sysmon_export.py -l LOGDIR errors [TARGET [CHECK]]

Never writes to the logs. Python 3.6+, standard library only, constant memory
(except -f table, which holds the result).
"""
import argparse
import csv
import datetime
import gzip
import io
import itertools
import json
import os
import re
import signal
import sys
import zlib

FILE_RE = re.compile(r"^([A-Za-z0-9_]+)-(\d{4})-(\d\d)-(\d\d)-(\d\d)\.tsv(?:\.gz)?\Z")
TS_RE = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d)(?::(\d\d)(?:\.(\d{1,6}))?)?\s*(Z|[+-]\d\d:?\d\d)?$")
EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


problems = []             # damaged files: exit status 1
warned = set()
MAX_LINE = 64 << 20


def warn(path, message, problem=True):
    """Once per file and message: files are read twice."""
    if problem and path not in problems:
        problems.append(path)
    if (path, message) not in warned:
        warned.add((path, message))
        sys.stderr.write("sysmon_export: warning: %s %s\n" % (path, message))


def die(message):
    sys.stderr.write("sysmon_export: %s\n" % message)
    sys.exit(2)


# --------------------------------------------------------------------------
# Values
# --------------------------------------------------------------------------
_zones = {}


def zone(text):
    if text not in _zones:
        if text == "Z":
            minutes = 0
        else:
            minutes = (int(text[1:3]) * 60 + int(text[-2:])) * (-1 if text[0] == "-" else 1)
        _zones[text] = datetime.timezone(datetime.timedelta(minutes=minutes))
    return _zones[text]


def parse_ts(text):
    """epoch seconds, or None. No offset means local time."""
    m = TS_RE.match(text)
    if not m:
        return None
    y, mo, d, h, mi, s, frac, off = m.groups()
    try:
        dt = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0),
                               int((frac or "0").ljust(6, "0")))
    except ValueError:
        return None
    if off is None:
        return dt.timestamp()
    return (dt.replace(tzinfo=zone(off)) - EPOCH).total_seconds()


def parse_when(text):
    if re.match(r"^\d{4}-\d\d-\d\d$", text):
        text += " 00:00"
    value = parse_ts(text)
    if value is None:
        raise argparse.ArgumentTypeError("use 'YYYY-MM-DD[ HH:MM[:SS]]'")
    return value


def parse_span(text):
    m = re.match(r"^(\d+(?:\.\d+)?)(s|m|min|h|d|w)$", text)
    if not m:
        raise argparse.ArgumentTypeError("use e.g. 30m, 2h, 1d")
    return float(m.group(1)) * {"s": 1, "m": 60, "min": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]


UNESCAPE = {"t": "\t", "n": "\n", "r": "\r", "0": "\0", "\\": "\\"}


def unescape(value):
    if "\\" not in value:
        return value
    if value == "\\N":
        return None
    return re.sub(r"\\(.)", lambda m: UNESCAPE.get(m.group(1), m.group(0)), value)


INTERVAL_RE = re.compile(
    r"^(?=.)(?:(-?\d+) years? ?)?(?:(-?\d+) mons? ?)?(?:(-?\d+) days? ?)?(?:([+-]?)(\d+):(\d\d):(\d\d(?:\.\d+)?))?$")
SIZE_RE = re.compile(r"^(\d+(?:\.\d+)?)([KMGTP])i?B?$|^(\d+)B$")


def numeric(value):
    """'12%' -> 12, '1.5Gi' -> bytes, '1 day 00:00:02' -> seconds; others unchanged."""
    if not value:
        return value
    if value[-1] == "%":
        try:
            return value[:-1] if float(value[:-1]) == float(value[:-1]) else value
        except ValueError:
            return value
    m = SIZE_RE.match(value)
    if m:
        return m.group(3) or str(int(float(m.group(1)) * 1024 ** ("KMGTP".index(m.group(2)) + 1)))
    value = re.sub(r"^(\d+)-(?=\d\d:\d\d:\d\d$)", r"\1 days ", value)     # ps: 1-02:03:04
    m = INTERVAL_RE.match(value) if ":" in value or value[-1] in "snry" else None
    if m:
        y, mo, d, sign, h, mi, s = m.groups()
        clock = int(h or 0) * 3600 + int(mi or 0) * 60 + float(s or 0)
        total = int(y or 0) * 31557600 + int(mo or 0) * 2592000 + int(d or 0) * 86400
        return ("%.6f" % (total + (-clock if sign == "-" else clock))).rstrip("0").rstrip(".")
    return value


# --------------------------------------------------------------------------
# Finding and reading files
# --------------------------------------------------------------------------
def find_files(root, check, start, end):
    """Sorted paths of one check (or all if None) that can hold data of [start, end]."""
    found = []

    def unreadable(exc):
        if not isinstance(exc, FileNotFoundError):   # else: just expired
            warn(exc.filename, "cannot be read: %s" % exc.strerror)

    for folder, dirs, names in os.walk(root, onerror=unreadable):
        depth = os.path.relpath(folder, root).count(os.sep) + 1 if folder != root else 0
        dirs[:] = sorted(d for d in dirs if depth < 3 and re.match(r"^\d{4}$" if depth == 0 else r"^\d\d$", d))
        if depth != 3:
            continue
        for name in names:
            m = FILE_RE.match(name)
            if not m or (check and m.group(1) != check):
                continue
            try:
                hour = datetime.datetime(*[int(x) for x in m.group(2, 3, 4, 5)]).timestamp()
            except (ValueError, OverflowError):
                continue                             # not one of ours
            # names are in the daemon's local time, which we do not know
            if (start is None or hour + 30 * 3600 > start) and (end is None or hour - 28 * 3600 < end):
                found.append((m.group(1), m.group(2, 3, 4, 5), not name.endswith(".gz"),
                              os.path.join(folder, name)))
    found.sort()
    # Order of names is not order of time (clock and time zone changes). Nothing in a
    # file is newer than its modification time, unless the clock was set back: a day.
    keep = []
    for name, _, _, path in found:
        try:
            if start is not None and os.path.getmtime(path) < start - 86400:
                continue
        except OSError:
            pass                                     # just compressed: open_log copes
        keep.append((name, path))
    return keep


def open_log(path, listed=()):
    for candidate in (path, path + ".gz"):     # may get compressed under our feet
        if candidate != path and candidate in listed:
            break                              # already read: its turn came before
        try:
            stream = (gzip.open if candidate.endswith(".gz") else open)(candidate, "rb")
        except FileNotFoundError:
            continue
        return io.TextIOWrapper(stream, encoding="utf-8", errors="replace", newline="\n")
    return None


def read_lines(path, listed=()):
    try:
        fh = open_log(path, listed)
    except OSError as exc:
        warn(path, "cannot be read: %s" % exc.strerror)
        return
    if fh is None:
        warn(path, "was removed while reading (expired?)", problem=False)
        return
    with fh:
        try:
            while True:
                line = fh.readline(MAX_LINE)
                if line.endswith("\n"):
                    yield line[:-1]
                elif len(line) >= MAX_LINE:
                    warn(path, "is damaged: no end of line, the rest is skipped")
                    return
                else:                           # end; or still being written
                    return
        except (EOFError, OSError, zlib.error) as exc:
            warn(path, "is damaged: %s" % exc)


def already_compressed(path):
    """A crash between the two steps of compression leaves the same data twice."""
    try:
        with open(path, "rb") as plain, open(path + ".gz", "rb") as raw:
            size, length = os.fstat(plain.fileno()).st_size, 0
            with gzip.GzipFile(fileobj=raw) as gz:
                for block in iter(lambda: gz.read(1 << 18), b""):
                    length += len(block)
                if length < size:
                    return False
                gz.seek(length - size)
                for block in iter(lambda: plain.read(1 << 18), b""):
                    if gz.read(len(block)) != block:
                        return False
                return size > 0
    except (OSError, EOFError, zlib.error):
        return False


def unique(names):
    """a, a, b -> a, a_2, b"""
    out = []
    for name in names:
        new, n = name, 1
        while new in out:
            n += 1
            new = "%s_%d" % (name, n)
        out.append(new)
    return out


def read_records(files, start, end):
    """Yields (kind, epoch, ts, run, payload, format); kind is 'data' or 'error'."""
    cache = (None, None)
    listed = set(path for _, path in files)
    for _, path in files:
        columns, fmt, bad, torn = None, "raw", 0, 0
        if path + ".gz" in listed and already_compressed(path):
            continue
        for line in read_lines(path, listed):
            if line.endswith("\t\\!torn"):
                torn += 1                        # cut short by a crash or a full disk
                continue
            if line.startswith("#!\t"):
                parts = line.split("\t", 3)
                epoch = parse_ts(parts[1]) if len(parts) == 4 else None
                if epoch is None:
                    bad += 1
                elif (start is None or epoch >= start) and (end is None or epoch < end):
                    yield "error", epoch, parts[1], parts[2], unescape(parts[3]) or "", fmt
                continue
            if line.startswith("#ts\t"):
                columns = unique([unescape(c) or "" for c in line.split("\t")[2:]])
                continue
            if line.startswith("# "):
                m = re.search(r" format=(\S+)", line)
                fmt = m.group(1) if m else fmt
                continue
            parts = line.split("\t")
            if cache[0] != parts[0]:
                cache = (parts[0], parse_ts(parts[0]))
            epoch = cache[1]
            if epoch is None or columns is None or len(parts) - 2 != len(columns):
                bad += 1
                continue
            if (start is None or epoch >= start) and (end is None or epoch < end):
                yield "data", epoch, parts[0], parts[1], (columns, parts[2:]), fmt
        if bad:
            warn(path, "is damaged: %d lines skipped" % bad)
        if torn:
            warn(path, "has %d lines cut short by a crash or a full disk: that run is incomplete" % torn, problem=False)


# --------------------------------------------------------------------------
# Parsers: turn raw command output into rows
# Each gets an iterator of (epoch, ts, run, line) and yields (epoch, ts, dict)
# --------------------------------------------------------------------------
WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def parse_raw(lines):
    for epoch, ts, run, line in lines:
        yield epoch, ts, {"line": line}


def parse_table(lines):
    """First line of a run is the header, the last column takes the rest (ps, df -P)."""
    last, header = None, []
    for epoch, ts, run, line in lines:
        if run != last:
            last, header = run, unique(line.replace("Mounted on", "Mounted_on").split())
            continue
        fields = line.split()
        if "STARTED" in header:                  # ps lstart is five words
            at = header.index("STARTED")
            if len(fields) > at + 4 and fields[at] in WEEKDAYS:
                fields[at:at + 5] = [" ".join(fields[at:at + 5])]
        if len(fields) > len(header) > 0:
            # keep the original spacing of the last column
            extra = len(fields) - len(header) + 1
            tail = re.search(r"(?:\S+\s+){%d}\S+\s*$" % (extra - 1), line)
            fields[len(header) - 1:] = [tail.group(0).strip() if tail else " ".join(fields[-extra:])]
        if fields:
            yield epoch, ts, dict(zip(header, fields), _sysmon_order=header, _sysmon_group=run)


def per_run(lines, handle):
    """Group kv style output: one row per run."""
    last, row, when = None, {}, None
    for epoch, ts, run, line in lines:
        if run != last:
            if row:
                yield when[0], when[1], dict(row, _sysmon_group=last)
            last, row, when = run, {}, (epoch, ts)
        handle(row, line)
    if row:
        yield when[0], when[1], dict(row, _sysmon_group=last)


def parse_kv(lines):
    def handle(row, line):
        key, _, value = line.partition(":") if ":" in line else line.partition(" ")
        if value.split():
            row[key.strip()] = value.split()[0]
    return per_run(lines, handle)


def parse_loadavg(lines):
    names = ("load1", "load5", "load15", "running", "processes", "last_pid")
    for epoch, ts, run, line in lines:
        fields = line.replace("/", " ").split()
        if len(fields) == len(names):
            yield epoch, ts, dict(zip(names, fields), _sysmon_group=run)


def parse_free(lines):
    last, header = None, []
    for epoch, ts, run, line in lines:
        if run != last:
            last, header = run, line.split()
            continue
        name, _, rest = line.partition(":")
        if rest:
            yield epoch, ts, dict(zip(header, rest.split()), kind=name, _sysmon_order=["kind"] + header, _sysmon_group=run)


CPU = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice")


def parse_procstat(lines):
    """One row per cpu; machine wide counters go to the row of 'cpu' (the total)."""
    def flush(rows, when, last):
        for name, row in rows.items():
            row["_sysmon_order"] = ["cpu"] + list(CPU)
            row["_sysmon_group"] = last
            yield when[0], when[1], row
    last, rows, when = None, {}, None
    for epoch, ts, run, line in lines:
        if run != last:
            for item in flush(rows, when, last):
                yield item
            last, rows, when = run, {}, (epoch, ts)
        fields = line.split()
        if not fields:
            continue
        if fields[0].startswith("cpu"):
            rows[fields[0]] = dict(zip(CPU, fields[1:]), cpu=fields[0])
        elif len(fields) == 2 and "cpu" in rows:
            rows["cpu"][fields[0]] = fields[1]
        elif fields[0] in ("intr", "softirq") and len(fields) > 1 and "cpu" in rows:
            rows["cpu"][fields[0] + "_total"] = fields[1]
    for item in flush(rows, when, last):
        yield item


def parse_iostat(lines):
    """One row per device, plus one 'avg-cpu' row per report. All rows of a
    report get the time of its first line, even if it arrived in pieces."""
    mode, header, at, report = None, [], None, 0
    for epoch, ts, run, line in lines:
        fields = line.split()
        if not fields or line.startswith("Linux "):
            mode = None if mode != "cpu" else "cpu-done"
        elif fields[0] == "avg-cpu:":
            at, report = (epoch, ts), report + 1
            mode, header = "cpu", fields[1:]
        elif fields[0].rstrip(":") == "Device":
            if mode not in ("cpu", "cpu-done"):
                at, report = (epoch, ts), report + 1
            mode, header = "dev", fields[1:]
        elif mode == "cpu" and len(fields) == len(header):
            yield at[0], at[1], dict(zip(header, fields), device="avg-cpu", _sysmon_order=["device"] + header,
                                     _sysmon_group=(run, report))
        elif mode == "dev" and len(fields) == len(header) + 1:
            yield at[0], at[1], dict(zip(header, fields[1:]), device=fields[0], _sysmon_order=["device"] + header,
                                     _sysmon_group=(run, report))


def parse_vmstat(lines):
    """The first report of a run is the average since boot: left out."""
    header, seen, skip, report = [], set(), None, 0
    for epoch, ts, run, line in lines:
        fields = line.split()
        if fields and fields[0].strip("-") == "procs" and run not in seen:
            skip = run                           # a new process, not a repeated header
        seen.add(run)
        if "swpd" in fields:
            header = fields
        elif header and len(fields) >= len(header) and fields[0].isdigit():
            if skip == run:
                skip = None
                continue
            report += 1
            yield epoch, ts, dict(zip(header, fields), _sysmon_order=header, _sysmon_group=(run, report))


def parse_mpstat(lines):
    header, clock, at, report = [], None, None, 0
    for epoch, ts, run, line in lines:
        fields = line.split()
        if not fields or fields[0].startswith("Average") or line.startswith("Linux "):
            continue
        if "CPU" in fields:
            header = fields[fields.index("CPU"):]
        elif header and len(fields) > len(header):
            now = (run, " ".join(fields[:-len(header)]), tuple(header))
            if now != clock:                     # a report can arrive in pieces
                clock, at, report = now, (epoch, ts), report + 1
            yield at[0], at[1], dict(zip(header, fields[-len(header):]), _sysmon_order=header, _sysmon_group=(run, report))


PARSERS = {"raw": parse_raw, "table": parse_table, "kv": parse_kv, "free": parse_free,
           "loadavg": parse_loadavg, "procstat": parse_procstat, "iostat": parse_iostat,
           "vmstat": parse_vmstat, "mpstat": parse_mpstat}


def rows_of(files, start, end, force):
    """Rows as (epoch, ts, dict). Parsing happens before time filtering, so that
    a range starting in the middle of a file still knows its headers."""
    wide = read_records(files, None, None)
    pending = []

    def lines(first, fmt):
        yield first
        for kind, epoch, ts, run, payload, f in wide:
            if kind != "data":
                continue
            if f != fmt:
                pending.append((kind, epoch, ts, run, payload, f))
                return
            yield epoch, ts, run, unescape(payload[1][0]) or ""

    while True:
        record = pending.pop() if pending else next(wide, None)
        if record is None:
            return
        kind, epoch, ts, run, payload, fmt = record
        if kind != "data":
            continue
        if fmt == "columns":
            if (start is None or epoch >= start) and (end is None or epoch < end):
                columns, values = payload
                row = dict(zip(columns, map(unescape, values)))
                row["_sysmon_order"] = columns
                row["_sysmon_group"] = run
                yield epoch, ts, row
            continue
        first = (epoch, ts, run, unescape(payload[1][0]) or "")
        for e, t, row in PARSERS.get(force or fmt, parse_raw)(lines(first, fmt)):
            row.setdefault("_sysmon_group", t)
            if (start is None or e >= start) and (end is None or e < end):
                yield e, t, row


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def shape(rows, args):
    """Applies --where, --columns and --numeric. Yields (epoch, ts, [names], dict, group)."""
    wanted = set(k for k, _ in args.where) | set(args.columns or ()) | set(args.pivot or ())
    wanted |= set(args.numeric or ()) - {"all"}
    any_row, names = False, []
    for epoch, ts, row in rows:
        order, group, any_row = row.pop("_sysmon_order", None), row.pop("_sysmon_group", None), True
        names = list(order) + [k for k in row if k not in order] if order else list(row)
        wanted.difference_update(names)
        if any(row.get(k) != (None if v == "\\N" else v) for k, v in args.where):
            continue
        if args.columns:
            names = args.columns
        if args.numeric:
            every = "all" in args.numeric
            row = {k: numeric(v) if every or k in args.numeric else v for k, v in row.items()}
        yield epoch, ts, names, row, group
    if any_row and wanted:                       # a typo must not look like "no data"
        die("no such column: %s" % ", ".join(sorted(wanted)))


def pivot(rows, spec):
    """One row per report, one column per value of KEY."""
    key, value = spec
    current, when, last = {}, None, None
    for epoch, ts, names, row, group in rows:
        if when is not None and group != last:
            yield when[0], when[1], list(current), current, last
            current, when = {}, None
        when, last = when or (epoch, ts), group
        name = row.get(key)
        name = "NULL" if name is None else name
        if name in current:
            die("--pivot: %r appears more than once at %s; narrow it down with --where" % (name, ts))
        current[name] = row.get(value)
    if when is not None:
        yield when[0], when[1], list(current), current, last


def show_time(epoch, ts, style):
    if style == "epoch":
        return "%.3f" % epoch
    if style == "plain":
        return ts[:19].replace("T", " ")
    if style == "utc":
        return (EPOCH + datetime.timedelta(seconds=epoch)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    if style == "iso":
        return re.sub(r"^(\S+) (\S+) ([+-]\d\d)(\d\d)$", r"\1T\2\3:\4", ts)
    return ts


def time_name(names):
    """A check may have its own column called datetime."""
    return unique(list(names) + ["log_datetime" if "datetime" in names else "datetime"])[-1]


def export(args, out):
    root = target_root(args, args.target)
    files = find_files(root, args.check, args.start, args.end)
    if not files:
        die("no logs of %s/%s for this time range" % (args.target, args.check))

    def rows():
        result = shape(rows_of(files, args.start, args.end, args.parser), args)
        return pivot(result, args.pivot) if args.pivot else result

    if args.format == "json":
        for epoch, ts, names, row, _ in rows():
            record = {time_name(names): show_time(epoch, ts, args.time)}
            record.update((n, row.get(n)) for n in names)
            out.write(json.dumps(record) + "\n")
        return
    # Columns can change inside the range (upgrade, config change): use the
    # union of all. Costs a second pass over the files instead of memory.
    if args.columns and not args.pivot:
        columns = args.columns
    else:
        seen = {}
        for _, _, names, _, _ in rows():
            for name in names:
                seen[name] = True
        columns = list(seen)
    head = [time_name(columns)] + columns

    def cells():
        for epoch, ts, _, row, _ in rows():
            yield [show_time(epoch, ts, args.time)] + [
                args.null if row.get(c) is None else row[c] for c in columns]

    def flat(cells_):
        return [re.sub(r"\s+", " ", c) for c in cells_]

    if args.format == "csv":
        # old Pythons leave a lone \r unquoted unless it is in the terminator
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\r\n")

        def put(row):
            writer.writerow(row)
            out.write(buf.getvalue()[:-2] + "\n")
            buf.seek(0)
            buf.truncate()
        put(head)
        for row in cells():
            put([c.replace("\0", "\\0") for c in row])      # csv cannot hold NUL
    elif args.format == "tsv":
        for row in itertools.chain([head], cells()):
            out.write("\t".join(flat(row)) + "\n")
    else:
        head = flat(head)
        data = [[c[:args.width] for c in flat(row)] for row in cells()]
        widths = [max([len(h)] + [len(r[i]) for r in data]) for i, h in enumerate(head)]
        for row in [head, ["-" * w for w in widths]] + data:
            out.write("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() + "\n")


def target_root(args, target):
    """TARGET is a directory under logdir, or a path (cluster with its own logdir)."""
    path = target if os.sep in target else os.path.join(args.logdir or ".", target)
    if not os.path.isdir(path):
        die("%s is not a directory (see: list)" % path)
    return path


def all_targets(args):
    if not os.path.isdir(args.logdir):
        die("%s is not a directory" % args.logdir)
    for name in sorted(os.listdir(args.logdir)):
        if os.path.isdir(os.path.join(args.logdir, name)):
            yield name


def list_logs(args, out):
    out.write("%-20s %-28s %6s %10s  %-13s  %s\n" % ("target", "check", "files", "size", "first", "last"))
    for target in ([args.target] if args.target else all_targets(args)):
        stats = {}
        for check, path in find_files(target_root(args, target), None, None, None):
            hour = re.search(r"(\d{4}-\d\d-\d\d)-(\d\d)\.tsv", path)
            hour = "%s %s" % hour.groups()
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            s = stats.setdefault(check, [0, 0, hour, hour])
            s[0], s[1], s[3] = s[0] + 1, s[1] + size, hour
        for check in sorted(stats):
            out.write("%-20s %-28s %6d %9dk  %-13s  %s\n" % (
                (target, check, stats[check][0], (stats[check][1] + 1023) // 1024) + tuple(stats[check][2:])))


def errors(args, out):
    for target in ([args.target] if args.target else all_targets(args)):
        files = find_files(target_root(args, target), args.check, args.start, args.end)
        if args.check and not files:
            die("no logs of %s/%s for this time range" % (target, args.check))
        for check, path in files:
            for kind, epoch, ts, run, payload, _ in read_records([(check, path)], args.start, args.end):
                if kind == "error":
                    out.write("%s\t%s\t%s\t%s\n" % (
                        show_time(epoch, ts, "log"), target, check, re.sub(r"\s+", " ", payload)))


def main():
    p = argparse.ArgumentParser(description="export system_monitoring_next logs")
    p.add_argument("-l", "--logdir", default=os.environ.get("SYSMON_LOGDIR"),
                   help="[global] logdir of the daemon (or environment SYSMON_LOGDIR)")
    sub = p.add_subparsers(dest="command", metavar="list|export|errors")

    def times(sp):
        sp.add_argument("--from", dest="start", type=parse_when, metavar="TIME", help="inclusive")
        sp.add_argument("--to", dest="end", type=parse_when, metavar="TIME", help="exclusive")
        sp.add_argument("--last", type=parse_span, metavar="SPAN", help="e.g. 30m, 2h, 1d")

    sp = sub.add_parser("list", help="what is there")
    sp.add_argument("target", nargs="?")
    sp = sub.add_parser("errors", help="failed runs")
    sp.add_argument("target", nargs="?")
    sp.add_argument("check", nargs="?")
    times(sp)
    sp = sub.add_parser("export", help="export one check")
    sp.add_argument("target", help="os, _daemon, a cluster name, or a directory")
    sp.add_argument("check")
    times(sp)
    sp.add_argument("-f", "--format", choices=("csv", "tsv", "json", "table"), default="csv")
    sp.add_argument("-o", "--output", help="file (default: stdout); replaced only on success")
    sp.add_argument("-c", "--columns", type=lambda s: s.split(","), help="col1,col2,...")
    sp.add_argument("-w", "--where", action="append", default=[], metavar="COL=VALUE")
    sp.add_argument("--pivot", metavar="KEY:VALUE", help="one column per KEY holding VALUE")
    sp.add_argument("-n", "--numeric", type=lambda s: s.split(","), metavar="COLUMNS",
                    help="col1,col2 or all: intervals -> seconds, 12%% -> 12, 1.5Gi -> bytes")
    sp.add_argument("--time", choices=("log", "iso", "plain", "utc", "epoch"), default="log",
                    help="log: 2026-11-25 15:42:25 +0200 (default), iso: 2026-11-25T15:42:25+02:00")
    sp.add_argument("--null", default="", help="text for NULL (default: empty)")
    sp.add_argument("--parser", choices=sorted(PARSERS), help="override the format stored in the log")
    sp.add_argument("--width", type=int, default=60, help="max column width of -f table")
    args = p.parse_args()
    if not args.command:
        p.error("list, export or errors?")
    if not args.logdir and not os.sep in (getattr(args, "target", None) or ""):
        p.error("--logdir (or SYSMON_LOGDIR) is required")
    if getattr(args, "last", None):
        if args.start or args.end:
            p.error("--last cannot be combined with --from/--to")
        args.start = datetime.datetime.now().timestamp() - args.last
    if getattr(args, "start", None) and getattr(args, "end", None) and args.start >= args.end:
        p.error("--from must be before --to")
    try:
        os.nice(10)                              # usually runs on the database server
    except OSError:
        pass
    if args.command != "export":
        (list_logs if args.command == "list" else errors)(args, sys.stdout)
        sys.stdout.flush()
        return
    for item in args.where:
        if "=" not in item:
            p.error("--where needs COL=VALUE")
    args.where = [tuple(item.split("=", 1)) for item in args.where]
    if args.pivot:
        if args.columns:
            p.error("--pivot and --columns cannot be combined")
        args.pivot = args.pivot.split(":", 1)
        if len(args.pivot) != 2:
            p.error("--pivot needs KEY:VALUE")
    if not args.output:
        export(args, sys.stdout)
        sys.stdout.flush()
        return
    target = args.output.encode("utf-8", "surrogateescape")      # whatever the locale
    mode = 0o640                                 # query texts are sensitive, like the logs
    if os.path.lexists(target):
        if os.path.islink(target) or not os.path.isfile(target):
            die("%s is not a regular file" % args.output)
        mode = os.stat(target).st_mode & 0o777
    tmp = target + b".tmp.%d" % os.getpid()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))      # removes tmp
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with io.open(fd, "w", encoding="utf-8", newline="") as out:
            if os.path.lexists(target):
                os.fchmod(fd, mode)
            export(args, out)
        if problems:
            die("damaged logs: %s not written" % args.output)
        os.replace(tmp, target)
    except OSError as exc:
        die(exc)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


if __name__ == "__main__":
    # whatever the locale: the data is UTF-8
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", newline="")
    sys.argv = [os.fsencode(a).decode("utf-8", "replace") for a in sys.argv]
    try:
        main()
        sys.exit(1 if problems else 0)
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), 1)
    except KeyboardInterrupt:
        sys.exit(130)
