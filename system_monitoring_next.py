#!/usr/bin/env python3
"""system_monitoring_next - small, safe system / PostgreSQL data collector.

Python 3.6+ standard library only. PostgreSQL is queried through psql (12+).

Safety rules this file is built around (see README.md):
  * A check never overlaps itself; the work queue cannot grow.
  * At most ONE psql session per cluster. A session that stops answering is
    never replaced while it is alive: its stdin is closed and we wait.
  * Every query has server side statement_timeout / lock_timeout, restored
    before each query.
  * The main loop does no file I/O, so psql output is always consumed (a backend
    blocked on sending ignores statement_timeout and keeps its locks). Should it
    stall anyway, a watchdog process kills the psql that is running a query.
  * Every command has a deadline; everything it started is killed after it.
  * Output, memory, log volume and free disk space are all bounded.
  * The kernel OOM killer is told to pick us first.
"""
import argparse
import collections
import configparser
import csv
import ctypes
import errno
import fcntl
import gzip
import hashlib
import io
import logging
import logging.handlers
import os
import queue
import re
import resource
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import zlib

VERSION = "1.0"
LOG = logging.getLogger("sysmon")
NAME_RE = re.compile(r"^[A-Za-z0-9_]+\Z")
FILE_RE = re.compile(r"^([A-Za-z0-9_]+)-(\d{4})-(\d\d)-(\d\d)-(\d\d)\.tsv(\.gz)?\Z")
FORMATS = ("raw", "table", "kv", "free", "loadavg", "procstat", "iostat", "vmstat", "mpstat")
OS_TARGET = "os"
SELF_TARGET = "_daemon"
# Smallest accepted values. The fault tests lower them; the config cannot.
MIN_FREE_FLOOR = 64 << 20
MIN_SIZE_FLOOR = 100 << 20
STALL_LIMIT = 5.0                  # main loop silent for this long: watchdog acts


class ConfigError(Exception):
    pass


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
def parse_duration(text):
    """'500ms', '2s', '5min', '1h', '2d', '1w' or plain seconds -> seconds."""
    m = re.match(r"^(\d+(?:\.\d+)?)\s*(ms|s|m|min|h|d|w)?$", text.strip())
    if not m:
        raise ConfigError("bad duration %r (examples: 500ms 2s 5min 1h 2d)" % text)
    unit = {"ms": 0.001, "s": 1, None: 1, "m": 60, "min": 60, "h": 3600, "d": 86400, "w": 604800}
    return float(m.group(1)) * unit[m.group(2)]


def parse_size(text):
    m = re.match(r"^(\d+(?:\.\d+)?)\s*([kmgt])i?b?$", text.strip().lower())
    if not m:
        raise ConfigError("bad size %r: number and unit required (examples: 500MB 20GB)" % text)
    return int(float(m.group(1)) * 1024 ** " kmgt".index(m.group(2)))


def parse_bool(text):
    value = text.strip().lower()
    if value in ("1", "on", "yes", "true"):
        return True
    if value in ("0", "off", "no", "false"):
        return False
    raise ConfigError("bad boolean %r" % text)


def parse_int(text):
    try:
        return int(text)
    except ValueError:
        raise ConfigError("bad integer %r" % text)


def is_ident(char):
    return char == "$" or char == "_" or char.isalnum() or ord(char) >= 0x80


def check_sql(sql):
    """Reject anything that could confuse the psql conversation.

    Not a validator: only verifies that quotes, comments and parentheses are
    closed and that there is no bare ';' or psql backslash command.
    """
    i, depth, n = 0, 0, len(sql)
    while i < n:
        c = sql[i]
        if c in "'\"":
            escapes = c == "'" and i and sql[i - 1] in "eE" and not (i > 1 and is_ident(sql[i - 2]))
            i += 1
            while i < n and sql[i] != c:
                i += 2 if escapes and sql[i] == "\\" else 1
            if i >= n:
                raise ConfigError("unterminated %s in query" % c)
        elif c == "$" and not (i and is_ident(sql[i - 1])):
            m = re.match(r"\$([A-Za-z_]\w*)?\$", sql[i:])
            if m:
                end = sql.find(m.group(0), i + len(m.group(0)))
                if end < 0:
                    raise ConfigError("unterminated %s in query" % m.group(0))
                i = end + len(m.group(0)) - 1
        elif sql.startswith("--", i):
            end = sql.find("\n", i)
            i = n if end < 0 else end
        elif sql.startswith("/*", i):
            end = sql.find("*/", i + 2)
            if end < 0:
                raise ConfigError("unterminated comment in query")
            if "/*" in sql[i + 2:end]:
                raise ConfigError("nested comments are not supported in queries")
            i = end + 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                raise ConfigError("unbalanced ) in query")
        elif c == ";":
            raise ConfigError("a check holds a single query: ';' is not allowed")
        elif c == "\\":
            raise ConfigError("backslash outside quotes is not allowed in a query")
        i += 1
    if depth:
        raise ConfigError("unbalanced ( in query")
    if "\0" in sql or len(sql.encode("utf-8")) > 32768:
        raise ConfigError("query is too long or contains NUL")


class Section(object):
    """Typed access to an ini section; complains about unknown keys (typos)."""

    def __init__(self, name, data):
        self.name, self.data, self.used = name, dict(data), set()

    def get(self, key, default=None, conv=str):
        self.used.add(key)
        if key not in self.data:
            return default
        try:
            return conv(self.data[key])
        except ConfigError as exc:
            raise ConfigError("[%s] %s: %s" % (self.name, key, exc))

    def finish(self):
        unknown = sorted(set(self.data) - self.used)
        if unknown:
            raise ConfigError("[%s] unknown setting(s): %s" % (self.name, ", ".join(unknown)))


class Cluster(object):
    pass


class Check(object):
    """One scheduled unit: a check bound to one target (os or a cluster)."""

    def __init__(self):
        self.cluster = None
        self.busy = False          # queued, running or stuck
        self.next_run = 0.0
        self.fails = 0
        self.runs = 0

    @property
    def label(self):
        return "%s/%s" % (self.target, self.name)

    def meta(self):
        return "# check=%s target=%s type=%s format=%s interval=%g" % (
            self.name, self.target, self.type, self.format, self.interval)


class Config(object):
    def __init__(self, path):
        self.path = path
        try:
            mode = os.stat(path).st_mode
            if mode & stat.S_IWOTH:
                raise ConfigError("%s is world writable: refusing to run commands from it" % path)
            parser = configparser.ConfigParser(
                interpolation=None, delimiters=("=",), comment_prefixes=("#",),
                inline_comment_prefixes=None, empty_lines_in_values=False, strict=True)
            parser.optionxform = str
            with io.open(path, encoding="utf-8") as fh:
                text = fh.read()
            bad = re.search(r"^[ \t]+#[>\-=&|#].*$", text, re.M)
            if bad:
                raise ConfigError("%r would be read as a comment: do not start a line with that operator"
                                  % bad.group(0).strip())
            parser.read_string(text)
        except (OSError, UnicodeDecodeError, configparser.Error) as exc:
            raise ConfigError("cannot read config: %s" % exc)

        if parser.defaults():
            raise ConfigError("[DEFAULT] is not supported")
        self.warnings = []
        fixed, clusters, checks = {}, [], []
        seen = set()
        for name in parser.sections():
            parts = name.split()
            section = Section(name, parser[name])
            if tuple(parts) in seen:
                raise ConfigError("section [%s] appears twice" % " ".join(parts))
            seen.add(tuple(parts))
            if len(parts) == 2 and parts[0] in ("cluster", "check") and NAME_RE.match(parts[1]):
                (clusters if parts[0] == "cluster" else checks).append((parts[1], section))
            elif name in ("global", "env", "vars", "retention", "limits", "postgres"):
                fixed[name] = section
            else:
                raise ConfigError("unknown section [%s]" % name)

        def sec(name):
            return fixed.get(name) or Section(name, {})

        glob = sec("global")
        self.logdir = glob.get("logdir")
        if not self.logdir or not os.path.isabs(self.logdir):
            raise ConfigError("[global] logdir must be an absolute path")
        self.logdir = os.path.normpath(self.logdir)
        self.pidfile = os.path.join(self.logdir, "pidfile")
        self.nice = glob.get("nice", 10, parse_int)
        glob.finish()
        if not 0 <= self.nice <= 19:
            raise ConfigError("[global] nice must be between 0 and 19")

        self.env = dict(sec("env").data)
        variables = dict(sec("vars").data)
        for key in variables:
            if not NAME_RE.match(key):
                raise ConfigError("[vars] bad name %r" % key)

        ret = sec("retention")
        self.compress_after = ret.get("compress_after", 3600.0, parse_duration)
        self.keep = ret.get("keep", 2 * 86400.0, parse_duration)
        self.max_size = ret.get("max_size_per_target", 10 * 1024 ** 3, parse_size)
        self.max_file_size = ret.get("max_file_size", 512 * 1024 ** 2, parse_size)
        self.min_free_space = ret.get("min_free_space", 2 * 1024 ** 3, parse_size)
        ret.finish()
        if self.keep < 3600 or self.compress_after < 60 or self.compress_after > self.keep:
            raise ConfigError("[retention] need keep >= 1h and 60s <= compress_after <= keep")
        if self.min_free_space < MIN_FREE_FLOOR:
            raise ConfigError("[retention] min_free_space must be at least %dMB" % (MIN_FREE_FLOOR >> 20))
        if self.max_size < MIN_SIZE_FLOOR:
            raise ConfigError("[retention] max_size_per_target must be at least %dMB" % (MIN_SIZE_FLOOR >> 20))
        if not 1 << 20 <= self.max_file_size <= self.max_size:
            raise ConfigError("[retention] need 1MB <= max_file_size <= max_size_per_target")

        lim = sec("limits")
        self.max_parallel = lim.get("max_parallel_commands", 4, parse_int)
        self.max_output = lim.get("max_output", 8 * 1024 ** 2, parse_size)
        self.max_rows = lim.get("max_rows", 100000, parse_int)
        self.max_memory = lim.get("max_memory", 1024 ** 3, parse_size)
        default_timeout = lim.get("command_timeout", 10.0, parse_duration)
        lim.finish()
        if not 100 <= self.max_rows <= 500000:
            raise ConfigError("[limits] max_rows must be between 100 and 500000")
        if not 1 <= self.max_parallel <= 32:
            raise ConfigError("[limits] max_parallel_commands must be between 1 and 32")
        if not 65536 <= self.max_output <= 64 << 20:
            raise ConfigError("[limits] max_output must be between 64kB and 64MB")
        if not max(256 << 20, 16 * self.max_output) <= self.max_memory <= 1 << 36:
            raise ConfigError("[limits] max_memory must be >= 256MB, >= 16 x max_output and <= 64GB")

        pg = sec("postgres")
        self.statement_timeout = pg.get("statement_timeout", 2.0, parse_duration)
        self.lock_timeout = pg.get("lock_timeout", 0.2, parse_duration)
        self.answer_grace = pg.get("answer_grace", 3.0, parse_duration)
        self.session_max_age = pg.get("session_max_age", 3600.0, parse_duration)
        self.psql = pg.get("psql", "psql")
        pg.finish()
        self._check_timeouts("[postgres]", self.statement_timeout, self.lock_timeout)
        if not 1 <= self.answer_grace <= 60 or not 60 <= self.session_max_age <= 7 * 86400:
            raise ConfigError("[postgres] need 1s <= answer_grace <= 60s and 60s <= session_max_age <= 7d")

        self.clusters = collections.OrderedDict()
        for name, section in clusters:
            if name in (OS_TARGET, SELF_TARGET):
                raise ConfigError("cluster name %r is reserved" % name)
            cl = Cluster()
            cl.name = name
            cl.host = section.get("host", "")
            cl.port = section.get("port", 5432, parse_int)
            cl.user = section.get("user", "postgres")
            cl.database = section.get("database", "postgres")
            cl.logdir = os.path.normpath(section.get("logdir", os.path.join(self.logdir, name)))
            cl.read_only = section.get("read_only", True, parse_bool)
            cl.enabled = section.get("enabled", True, parse_bool)
            section.finish()
            if not 1 <= cl.port <= 65535:
                raise ConfigError("[cluster %s] bad port" % name)
            if "\0" in cl.host + cl.user + cl.database:
                raise ConfigError("[cluster %s] NUL character" % name)
            if not os.path.isabs(cl.logdir):
                raise ConfigError("[cluster %s] logdir must be absolute" % name)
            self.clusters[name] = cl

        for path in [self.logdir] + [c.logdir for c in self.clusters.values()]:
            if any(ord(c) < 32 or ord(c) > 126 for c in path):
                raise ConfigError("log directories must be plain ASCII: %r" % path)
        self.roots = collections.OrderedDict()
        self.roots[OS_TARGET] = os.path.join(self.logdir, OS_TARGET)
        self.roots[SELF_TARGET] = os.path.join(self.logdir, SELF_TARGET)
        for cl in self.clusters.values():
            self.roots[cl.name] = cl.logdir
        real = sorted(os.path.realpath(p) + os.sep for p in self.roots.values())
        for a, b in zip(real, real[1:]):
            if b.startswith(a):
                raise ConfigError("log directories may not be equal or nested: %s and %s" % (a, b))

        def expand(text):
            for _ in range(10):
                new = re.sub(r"@([A-Za-z0-9_]+)", lambda m: variables.get(m.group(1), m.group(0)), text)
                if new == text:
                    break
                text = new
            return text

        self.checks = []
        for name, section in checks:
            self._add_check(name, section, expand, default_timeout)
        if not self.checks:
            raise ConfigError("there are no enabled checks")
        self.keep_for = {}
        for chk in self.checks:
            if chk.keep is not None:
                self.keep_for[(chk.target, chk.name)] = chk.keep

    @staticmethod
    def _check_timeouts(where, statement, lock):
        # zero means "no limit" to PostgreSQL, so it is never acceptable here
        if not 0.01 <= lock < statement <= 60:
            raise ConfigError("%s need 10ms <= lock_timeout < statement_timeout <= 60s" % where)

    def _add_check(self, name, section, expand, default_timeout):
        where = "[check %s]" % name
        enabled = section.get("enabled", True, parse_bool)
        ctype = section.get("type")
        base = {
            "query": section.get("query"), "exec": section.get("exec"), "file": section.get("file")}
        if ctype is None:
            ctype = "query" if base["query"] else "file" if base["file"] else "command"
        if ctype not in ("query", "command", "persistent", "file", "pg_processes"):
            raise ConfigError("%s unknown type %r" % (where, ctype))
        needs = {"query": "query", "command": "exec", "persistent": "exec", "file": "file"}.get(ctype)
        for key, value in base.items():
            if (value is not None) != (key == needs):
                raise ConfigError("%s type %s needs %s" % (
                    where, ctype, "only '%s'" % needs if needs else "no exec/query/file"))
        interval = section.get("interval", 0.0, parse_duration)
        if ctype != "persistent" and interval < 1:
            raise ConfigError("%s interval must be at least 1s" % where)
        fmt = section.get("format", "raw")
        if fmt not in FORMATS:
            raise ConfigError("%s format must be one of: %s" % (where, ", ".join(FORMATS)))
        if ctype in ("query", "pg_processes"):
            fmt = "columns"
        timeout = section.get("timeout", default_timeout, parse_duration)
        if not 0 < timeout <= 600:
            raise ConfigError("%s timeout must be between 0 and 10min" % where)
        keep = section.get("keep", None, parse_duration)
        if keep is not None and keep < 3600:
            raise ConfigError("%s keep must be at least 1h" % where)
        st = section.get("statement_timeout", self.statement_timeout, parse_duration)
        lt = section.get("lock_timeout", self.lock_timeout, parse_duration)
        self._check_timeouts(where, st, lt)
        wanted = section.get("clusters")
        section.finish()
        ignored = {"query": ("timeout", "format"), "persistent": ("interval", "timeout"),
                   "pg_processes": ("format",)}.get(ctype, ())
        if ctype != "query":
            ignored += ("statement_timeout", "lock_timeout")
        for key in ignored:
            if key in section.data:
                raise ConfigError("%s %s has no meaning for type %s" % (where, key, ctype))
        if wanted is not None and not wanted.replace(",", " ").split():
            raise ConfigError("%s clusters is empty" % where)

        targets = [None]
        if ctype == "query":
            names = wanted.replace(",", " ").split() if wanted else list(self.clusters)
            for cname in names:
                if cname not in self.clusters:
                    raise ConfigError("%s unknown cluster %r" % (where, cname))
            if not names:
                raise ConfigError("%s needs at least one [cluster NAME] section" % where)
            targets = [self.clusters[c] for c in collections.OrderedDict.fromkeys(names)]
        elif wanted:
            raise ConfigError("%s 'clusters' only applies to query checks" % where)

        body = base[needs] if needs else ""
        body = expand(body).strip()
        for unknown in re.findall(r"(?<![\w@])@[A-Za-z]\w*", body):
            self.warnings.append("%s %s is not defined in [vars], left as it is" % (where, unknown))
        if ctype == "query":
            body = body.rstrip("; \n\t")
            try:
                check_sql(body)
            except ConfigError as exc:
                raise ConfigError("%s %s" % (where, exc))
        if needs and not body:
            raise ConfigError("%s %s is empty" % (where, needs))
        if ctype == "file" and not os.path.isabs(body):
            raise ConfigError("%s file must be an absolute path" % where)
        if not enabled:
            return
        for cl in targets:
            if cl is not None and not cl.enabled:
                continue
            chk = Check()
            chk.name, chk.type, chk.body, chk.interval = name, ctype, body, interval
            chk.format, chk.timeout, chk.keep = fmt, timeout, keep
            chk.statement_timeout, chk.lock_timeout = st, lt
            chk.cluster = cl
            chk.target = cl.name if cl is not None else OS_TARGET
            chk.skip_logged, chk.crashes, chk.disabled_until = False, 0, 0.0
            self.checks.append(chk)


# --------------------------------------------------------------------------
# Log files
# --------------------------------------------------------------------------
ESCAPES = {"\\": "\\\\", "\t": "\\t", "\n": "\\n", "\r": "\\r", "\0": "\\0"}
ESCAPE_RE = re.compile("[\\\\\t\n\r\0]")


def escape(value):
    """Same escaping as COPY text format: one record is always one line."""
    return ESCAPE_RE.sub(lambda m: ESCAPES[m.group(0)], value)


def stamp(epoch):
    return time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(epoch))


# Ends a line that a crash or a full disk cut short. escape() never produces
# this text, so readers can tell it and drop the line.
TORN = b"\t\\!torn\n"


class Sink(threading.Thread):
    """Writes the files of one target, in its own thread: a hung filesystem
    blocks neither the main loop nor the other targets.

    Files are opened per write: nothing is held open, so cleanup and rotation
    can never race with a file handle.
    """

    def __init__(self, writer, target, root, may_create):
        super(Sink, self).__init__(name="sink-" + target)
        self.daemon = True
        self.writer, self.config, self.target, self.root = writer, writer.config, target, root
        self.may_create = may_create
        self.items = queue.Queue(maxsize=2000)
        self.headers = {}
        self.torn = set()
        self.hour = None
        self.pending = 0             # bytes queued; guarded by writer.lock
        self.space = (-1e9, True)
        self.over_quota = False      # set by Maintenance

    def run(self):
        while True:
            item = self.items.get()
            try:
                if item is None:
                    return
                if not self.store(*item):
                    self.writer.count_drop()
            except Exception as exc:
                self.writer.count_drop()
                throttled("write:" + self.target, "cannot write logs of %s: %s", self.target, exc)
            finally:
                if item is not None:
                    self.writer.release(self, item)
                self.items.task_done()

    def has_space(self):
        now = time.monotonic()
        checked, good = self.space
        if now - checked >= 5:
            st = os.statvfs(self.root)
            good = st.f_bavail * st.f_frsize >= self.config.min_free_space
            if st.f_files and st.f_favail < 1000:
                good = False
            self.space = (now, good)
        return good

    def store(self, name, header, preamble, body):
        if not os.path.isdir(self.root):
            if not self.may_create:
                raise OSError(errno.ENOENT, "log directory does not exist (not mounted?)", self.root)
            os.mkdir(self.root, 0o750)
        if self.over_quota or not self.has_space():
            throttled("space:" + self.target, "NOT writing logs of %s: %s", self.target,
                      "max_size_per_target reached" if self.over_quota
                      else "free space or inodes of the filesystem too low")
            return False
        lt = time.localtime()
        hour = time.strftime("%Y-%m-%d-%H", lt)
        if hour != self.hour:
            self.hour = hour
            self.headers.clear()
            self.torn.clear()
        folder = os.path.join(self.root, time.strftime("%Y/%m/%d", lt))
        path = os.path.join(folder, "%s-%s.tsv" % (name, hour))
        if not os.path.isdir(folder):
            os.makedirs(folder, 0o750)
        fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        try:
            size = os.fstat(fd).st_size
            data = body
            if not size:
                self.headers.pop(path, None)         # removed by somebody
            if header is not None and self.headers.get(path) != header:
                data = header + preamble + body
            if size + len(data) > self.config.max_file_size:
                throttled("big:%s/%s" % (self.target, name),
                          "%s/%s: file of this hour reached max_file_size, dropping", self.target, name)
                return False
            if size and (path not in self.headers or path in self.torn) and os.pread(fd, 1, size - 1) != b"\n":
                data = TORN + data
            view = memoryview(data)
            self.torn.add(path)
            while view:
                view = view[os.write(fd, view):]
            self.torn.discard(path)
        finally:
            os.close(fd)
        if header is not None:
            self.headers[path] = header
        return True


class Writer(object):
    """Formats records and queues them for the sinks. Never blocks; when a
    filesystem is too slow the records are dropped and counted."""

    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.pending = self.dropped = 0
        # per target, so that one hung filesystem does not starve the others, and in total
        self.limit = max(4 * config.max_output, 32 << 20)
        self.total = max(self.limit, config.max_memory // 4)
        self.sinks = {}
        for target, root in config.roots.items():
            self.sinks[target] = Sink(self, target, root, os.path.dirname(root) == config.logdir)

    def start(self):
        for sink in self.sinks.values():
            sink.start()

    def count_drop(self):
        with self.lock:
            self.dropped += 1

    @staticmethod
    def size(item):
        return 256 + sum(len(part) for part in item[1:] if part)

    def release(self, sink, item):
        with self.lock:
            self.pending -= self.size(item)
            sink.pending -= self.size(item)

    def write(self, target, name, meta, columns, ts, run, rows, errors=(), preamble=()):
        prefix = "%s\t%s\t" % (stamp(ts), run)
        out = [prefix + "\t".join(row) for row in rows]
        out += ["#!\t" + prefix + escape(message) for message in errors]
        header = None
        if columns is not None:
            header = "%s\n%s\n" % (meta, "\t".join(["#ts", "run"] + [escape(c) for c in columns]))
            header = header.encode("utf-8", "replace")
        if not out and header is None:
            return True
        body = "".join(line + "\n" for line in out).encode("utf-8", "replace")
        before = "".join(prefix + line + "\n" for line in preamble).encode("utf-8", "replace")
        item = (name, header, before, body)
        size = self.size(item)
        sink = self.sinks[target]
        with self.lock:
            fits = sink.pending + size <= self.limit and self.pending + size <= self.total
            if fits:
                self.pending += size
                sink.pending += size
        if fits:
            try:
                sink.items.put_nowait(item)
                return True
            except queue.Full:
                self.release(sink, item)
        self.count_drop()
        if rows:                         # at least say so in the log, if that fits
            self.write(target, name, meta, None, ts, run, [], list(errors) + [
                "%d rows dropped: log files cannot be written fast enough" % len(rows)])
        throttled("backlog", "log files cannot be written fast enough (hung filesystem?): dropping data")
        return False

    def flush(self, timeout):
        """True when everything queued so far has been handled."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not any(s.items.unfinished_tasks for s in self.sinks.values()):
                return True
            time.sleep(0.02)
        return False


class Maintenance(threading.Thread):
    """Compresses and expires the log files of one target, and nothing else.

    Only regular files whose name AND directory match our layout are touched;
    symlinks are never followed.
    """

    def __init__(self, config, sink):
        super(Maintenance, self).__init__(name="maintenance-" + sink.target)
        self.daemon = True
        self.config, self.sink, self.root, self.target = config, sink, sink.root, sink.target
        self.stop = threading.Event()
        self.drift = time.time() - time.monotonic()
        self.hold_until = 0.0
        self.damaged = {}            # path of .gz -> mtime: do not read it again and again

    def run(self):
        while not self.stop.wait(5):
            try:
                self.cycle()
            except Exception as exc:
                throttled("maint:" + self.target, "cleanup of %s failed (will retry): %s: %s",
                          self.target, type(exc).__name__, exc)
            if self.stop.wait(55):
                return

    @staticmethod
    def subdirs(path, pattern):
        try:
            names = sorted(os.listdir(path))
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                throttled("list:" + path, "cannot read %s: %s", path, exc)
            return
        for name in names:
            full = os.path.join(path, name)
            try:
                if re.match(pattern, name) and stat.S_ISDIR(os.lstat(full).st_mode):
                    yield name, full
            except OSError as exc:
                throttled("list:" + path, "cannot read %s: %s", full, exc)

    def day_dirs(self):
        for year, ydir in self.subdirs(self.root, r"^\d{4}$"):
            for month, mdir in self.subdirs(ydir, r"^\d\d$"):
                for day, ddir in self.subdirs(mdir, r"^\d\d$"):
                    yield (year, month, day), (ddir, mdir, ydir)

    def day_files(self, date, folder):
        """[(hour, size, mtime, check, path)] of our own files in one day directory."""
        found = []
        try:
            names = os.listdir(folder)
        except OSError as exc:
            throttled("list:" + folder, "cannot read %s: %s", folder, exc)
            return found
        for name in names:
            path = os.path.join(folder, name)
            m = FILE_RE.match(name)
            if m and m.group(2, 3, 4) == date:
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode):
                    found.append(("-".join(m.group(2, 3, 4, 5)), st.st_size, st.st_mtime, m.group(1), path))
            elif name.endswith(".tsv.gz.tmp") and FILE_RE.match(name[:-4]):
                self.unlink(path)              # left by a crash during compression
        return found

    @staticmethod
    def prune(dirs):
        today = time.strftime("%Y/%m/%d")
        for path in dirs:
            if today.startswith("/".join(path.split(os.sep)[-3:])):
                return
            try:
                os.rmdir(path)                 # only ever removes empty directories
            except OSError:
                return

    @staticmethod
    def unlink(path):
        try:
            os.unlink(path)
            return True
        except OSError as exc:
            throttled("unlink", "cannot remove %s: %s", path, exc)
            return False

    def may_expire(self, now):
        """False for a day after the clock jumped: a wrong date must not expire everything."""
        drift = now - time.monotonic()
        if abs(drift - self.drift) > 3600:
            LOG.warning("%s: system clock jumped by %.0fs, not expiring logs for a day",
                        self.target, drift - self.drift)
            self.hold_until = time.monotonic() + 86400
        self.drift = drift
        return time.monotonic() >= self.hold_until

    def cycle(self):
        now = time.time()
        expire = self.may_expire(now)
        current = time.strftime("%Y-%m-%d-%H", time.localtime(now))
        total, days = 0, []
        for date, dirs in self.day_dirs():
            for hour, size, mtime, check, path in self.day_files(date, dirs[0]):
                if self.stop.is_set():
                    return
                try:
                    age = now - mtime
                    if hour != current:
                        if expire and age > self.config.keep_for.get((self.target, check), self.config.keep):
                            if self.unlink(path):
                                continue
                        elif path.endswith(".tsv") and age > self.config.compress_after:
                            size = self.compress(path)
                except Exception as exc:
                    throttled("file:" + self.target, "cannot process %s: %s: %s",
                              path, type(exc).__name__, exc)
                total += size
            days.append((date, dirs))
            self.prune(dirs)
        # over the limit: oldest hours first, never the current one
        for date, dirs in days:
            if total <= self.config.max_size:
                break
            for hour, size, _, _, path in sorted(self.day_files(date, dirs[0])):
                if total <= self.config.max_size or hour == current:
                    break
                if self.unlink(path):
                    total -= size
                    throttled("quota:" + self.target, "%s is over max_size_per_target: removing oldest logs (%s)",
                              self.target, path)
        self.sink.over_quota = total > self.config.max_size

    @staticmethod
    def already_inside(path, size, final):
        """Does the .gz end with the contents of path? (crash after rename, before unlink)"""
        length = 0
        with gzip.open(final, "rb") as gz:
            while True:
                block = gz.read(1 << 18)
                if not block:
                    break
                length += len(block)
        if length < size:
            return False
        skip = length - size
        with gzip.open(final, "rb") as gz, open(path, "rb") as plain:
            while skip:
                skip -= len(gz.read(min(skip, 1 << 18)))
            while True:
                block = plain.read(1 << 18)
                if not block:
                    return True
                if gz.read(len(block)) != block:
                    return False

    def compress(self, path):
        """Returns the size of the result."""
        final, tmp = path + ".gz", path + ".gz.tmp"
        st = os.lstat(path)
        merge = os.path.lexists(final)
        if merge and not stat.S_ISREG(os.lstat(final).st_mode):
            raise OSError(errno.EEXIST, "not a regular file", final)
        if merge:
            mtime = os.lstat(final).st_mtime_ns
            if self.damaged.get(final) == mtime:
                raise OSError(errno.EIO, "existing .gz is damaged, leaving both", final)
            try:
                done = self.already_inside(path, st.st_size, final)
            except (OSError, EOFError, zlib.error):
                if len(self.damaged) > 1000:
                    self.damaged.clear()
                self.damaged[final] = mtime
                raise OSError(errno.EIO, "existing .gz is damaged, leaving both", final)
            if done:
                self.unlink(path)
                return os.lstat(final).st_size
        free = os.statvfs(os.path.dirname(path))
        if free.f_bavail * free.f_frsize < st.st_size + self.config.min_free_space // 2:
            raise OSError(errno.ENOSPC, "not enough free space to compress")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        try:
            with os.fdopen(fd, "wb") as out:
                if merge:                        # clock went back: keep both parts
                    with open(final, "rb") as old:
                        shutil.copyfileobj(old, out, 1 << 18)
                with open(path, "rb") as src, gzip.GzipFile("", "wb", 5, out) as gz:
                    while True:
                        block = src.read(1 << 18)
                        if not block:
                            break
                        gz.write(block)
                        if self.stop.wait(0.005):   # gentle on cpu/io, and quick to stop
                            raise OSError(errno.EINTR, "interrupted")
                out.flush()
                os.fsync(out.fileno())
            if os.lstat(path).st_size != st.st_size:
                raise OSError(errno.EAGAIN, "file grew while compressing")
            os.utime(tmp, (st.st_mtime, st.st_mtime))
            os.rename(tmp, final)
        except BaseException:
            self.unlink(tmp)
            raise
        self.unlink(path)
        return os.lstat(final).st_size


_last_message = {}


class QueuedLog(logging.Handler):
    """stderr or the log file may block (hung disk, stuck pipe): never in the main loop."""

    def __init__(self, target):
        super(QueuedLog, self).__init__()
        self.target = target
        self.items = queue.Queue(maxsize=1000)
        thread = threading.Thread(target=self.work, name="log")
        thread.daemon = True
        thread.start()

    def emit(self, record):
        try:
            self.items.put_nowait(record)
        except queue.Full:
            pass

    def work(self):
        while True:
            record = self.items.get()
            try:
                self.target.handle(record)
            except Exception:
                pass
            finally:
                self.items.task_done()

    def wait(self, timeout):
        deadline = time.monotonic() + timeout
        while self.items.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.02)


def throttled(key, message, *args):
    """Log at most once a minute per key, so failures cannot flood the log."""
    now = time.monotonic()
    if now - _last_message.get(key, -1e9) >= 60:
        _last_message[key] = now
        LOG.warning(message, *args)


# --------------------------------------------------------------------------
# Child processes
# --------------------------------------------------------------------------
def set_nonblocking(fd):
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)


def read_some(fd):
    """bytes, b'' at end of file, or None when there is nothing to read now."""
    try:
        return os.read(fd, 65536)
    except (BlockingIOError, InterruptedError):
        return None
    except OSError:
        return b""


def has_exited(proc):
    """True when the child exited, WITHOUT reaping it.

    While the zombie is kept its pid (== process group and session id) cannot
    be reused, which is what makes send_session() below safe.
    """
    if proc.returncode is not None:
        return True
    try:
        return os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    except ChildProcessError:
        proc.lost = True             # somebody else reaped it: the pid is no longer ours
        return True


def is_postgres(pid):
    """True for any PostgreSQL server process, and whenever we cannot tell.

    A signal to a backend can crash-restart the whole cluster and one to the
    postmaster stops it, so in doubt the answer is yes.
    """
    comm = read_proc(str(pid), "comm").strip()
    if not comm or re.search("postgres|postmaster", comm):
        return True
    try:
        exe = os.readlink("/proc/%s/exe" % pid)
    except PermissionError:
        exe = ""                     # another user's: then the signal fails as well
    except OSError:
        return True                  # gone, or a zombie
    return re.search("postgres|postmaster|/edb-postgres", os.path.basename(exe)) is not None


def may_signal(pid):
    """False for PostgreSQL, for everything below it, and whenever we cannot tell.

    A server is recognised by its name, or by where it runs: whatever its binary
    is called, it changes to its data directory, and what it starts (restore_command,
    archive_command) inherits that. All we start, starts in /. So only processes in
    /, /proc or /sys are ever signalled.
    """
    if is_postgres(pid):
        return False
    try:
        cwd = os.readlink("/proc/%s/cwd" % pid)
    except OSError:
        return False
    if cwd != "/" and not re.match(r"^/(proc|sys)(/|\Z)", cwd):
        return False
    for _ in range(64):              # ancestors, up to us or to init
        st = proc_stat(pid)
        if st is None:
            return False
        pid = st[1]
        if pid <= 1 or pid == os.getpid():
            return True
        if is_postgres(pid):
            return False
    return False


def send(pid, sig, starttime=None):
    """THE ONLY PLACE that signals other processes. One process at a time, never
    a group, never PostgreSQL or its children, never pid <= 1, never a recycled pid."""
    if pid <= 1 or pid == os.getpid() or not may_signal(pid):
        return
    st = proc_stat(pid)
    if st is None or st[0] == "Z" or (starttime is not None and st[3] != starttime):
        return
    try:
        os.kill(pid, sig)
    except OSError:
        pass


def send_session(proc, sig):
    """Signals every member of the session led by our child.

    killpg() is not used: it cannot leave out a PostgreSQL that a check started.
    The child is not reaped yet, so its pid cannot be anybody else's session."""
    if proc.returncode is not None or getattr(proc, "lost", False):
        return
    for name in os.listdir("/proc"):
        if name.isdigit():
            st = proc_stat(name)
            if st and st[2] == proc.pid:
                send(int(name), sig, st[3])


def encode_args(args):
    return [a.encode("utf-8", "surrogateescape") if isinstance(a, str) else a for a in args]


def proc_stat(pid):
    """(state, ppid, session, starttime) or None"""
    text = read_proc(str(pid), "stat")
    fields = text[text.rfind(")") + 1:].split()
    if len(fields) < 20:
        return None
    return fields[0], int(fields[1]), int(fields[3]), fields[19]


def direct_children():
    """pids of our children, including adopted ones (see become_subreaper)"""
    pids, found = [], False
    try:
        for tid in os.listdir("/proc/self/task"):
            try:
                with open("/proc/self/task/%s/children" % tid) as fh:
                    pids += [int(x) for x in fh.read().split()]
                    found = True
            except FileNotFoundError:
                pass
    except OSError:
        return []
    if not found:                    # kernel without CONFIG_PROC_CHILDREN
        me = os.getpid()
        for name in os.listdir("/proc"):
            if name.isdigit():
                st = proc_stat(name)
                if st and st[1] == me:
                    pids.append(int(name))
    return pids


def is_stray(pid, marker):
    """Could this orphan, adopted by us, come from one of our commands? They inherit
    a random marker in their environment; setuid programs hide it."""
    if is_postgres(pid):
        return False
    try:
        with open("/proc/%d/environ" % pid, "rb") as fh:
            return marker.encode() in fh.read(1 << 20)
    except FileNotFoundError:
        # gone, or hidden (hidepid). init adopts strangers too: then no guessing
        return os.getpid() != 1 and not os.path.exists("/proc/%d" % pid)
    except OSError:
        return os.getpid() != 1


def become_subreaper():
    """Orphans of our commands become our children instead of init's, so that
    what escapes the process group (timeout, setsid, sudo) is not lost."""
    try:
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0):
            raise OSError(ctypes.get_errno(), "prctl failed")
    except (OSError, AttributeError) as exc:
        LOG.warning("cannot become subreaper: %s", exc)


class Command(object):
    """A running command / persistent check."""

    def __init__(self, daemon, check, argv):
        self.daemon, self.check = daemon, check
        self.started, self.ts = time.monotonic(), time.time()
        self.run = daemon.run_id(self.ts)
        self.buf, self.err = bytearray(), bytearray()
        self.lines = 0
        self.truncated = self.paused = False
        self.window = self.started
        self.window_bytes = 0
        self.preamble = {}
        self.interrupted = False
        self.term_sent = self.kill_sent = self.exit_seen = self.kill_again = None
        self.proc = subprocess.Popen(
            encode_args(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, start_new_session=True, env=daemon.command_env, cwd="/")
        self.pipes = {}
        self.out_fd, self.err_fd = self.proc.stdout.fileno(), self.proc.stderr.fileno()
        try:
            for pipe, fn in ((self.proc.stdout, self.on_out), (self.proc.stderr, self.on_err)):
                set_nonblocking(pipe.fileno())
                daemon.selector.register(pipe.fileno(), selectors.EVENT_READ, fn)
                self.pipes[pipe.fileno()] = pipe
        except Exception:
            for fd in list(self.pipes):
                self.close_fd(fd)
            self.proc.stdout.close()
            self.proc.stderr.close()
            send_session(self.proc, signal.SIGKILL)
            raise                    # the zombie is reaped by kill_orphans()

    @property
    def persistent(self):
        return self.check.type == "persistent"

    def close_fd(self, fd):
        pipe = self.pipes.pop(fd, None)
        if pipe is not None:
            if not (self.paused and fd == self.out_fd):
                self.daemon.selector.unregister(fd)
            pipe.close()

    def on_err(self):
        if self.err_fd not in self.pipes:
            return False
        data = read_some(self.err_fd)
        if data == b"":
            self.close_fd(self.err_fd)
        elif data:
            self.err += data[:max(0, 4096 - len(self.err))]
        return bool(data)

    def on_out(self):
        if self.out_fd not in self.pipes:
            return False
        data = read_some(self.out_fd)
        if data is None:
            return False
        if not data:
            self.close_fd(self.out_fd)
            return False
        limit = self.daemon.config.max_output
        if self.persistent:
            self.buf += data
            # what counts is what reaches the disk, line prefix included
            self.window_bytes += len(data) + 48 * data.count(b"\n")
            self.flush_lines()
            if self.window_bytes > limit and not self.paused:
                # stop reading: the pipe fills and the producer blocks. No cpu, no disk.
                self.daemon.selector.unregister(self.out_fd)
                self.paused = True
                throttled("flood:" + self.check.label,
                          "%s writes more than max_output per minute: pausing it", self.check.label)
        else:
            room = max(0, limit - len(self.buf))
            self.buf += data[:room]
            self.truncated = self.truncated or len(data) > room
        return True

    def flush_lines(self, final=False):
        cut = self.buf.rfind(b"\n") + 1
        if final or len(self.buf) - cut > 65536:
            cut = len(self.buf)
        if not cut:
            return
        rows = text_rows(bytes(self.buf[:cut]))
        del self.buf[:cut]
        self.lines += len(rows)
        # mpstat and vmstat -n print their header once per process: repeat it
        # at the start of every file, so that each file can be read by itself
        preamble = list(self.preamble.values())
        if self.check.format in ("mpstat", "vmstat"):
            word = "CPU" if self.check.format == "mpstat" else "swpd"
            for row in rows:
                if word in row[0].split():
                    self.preamble[word] = row[0]
        self.daemon.writer.write(self.check.target, self.check.name, self.check.meta(), ("line",),
                                 time.time(), self.run, rows, preamble=preamble)

    def take_errors(self):
        text = bytes(self.err).decode("utf-8", "replace")
        self.err = bytearray()
        return [" ".join(line.split())[:500] for line in text.split("\n") if line.strip()][:5]

    def tick(self, now):
        """Returns True once the process, and everything it started, is gone."""
        if self.persistent:
            if self.paused and now - self.window >= 60 and self.out_fd in self.pipes:
                self.paused = False
                self.daemon.selector.register(self.out_fd, selectors.EVENT_READ, self.on_out)
            if self.err and now - self.window >= 5:
                errors = self.take_errors()
                self.daemon.writer.write(self.check.target, self.check.name, self.check.meta(), None,
                                         time.time(), self.run, [], errors[:1])
                throttled("check:" + self.check.label, "%s: %s", self.check.label, errors[:1])
        if now - self.window >= 60:
            self.window, self.window_bytes = now, 0
        if self.exit_seen is None and not has_exited(self.proc):
            if self.persistent:
                if self.out_fd not in self.pipes and self.term_sent is None:
                    self.terminate(now)
            elif now - self.started > self.check.timeout and self.term_sent is None:
                self.terminate(now)
            if self.term_sent is not None and now - self.term_sent > 2:
                if self.kill_sent is None:
                    self.kill_sent = now
                # each time reads all of /proc: not on every tick
                if self.kill_again is None or now - self.kill_again >= 5:
                    self.kill_again = now
                    send_session(self.proc, signal.SIGKILL)
                self.complain(now)
            return False
        if self.exit_seen is None:
            self.exit_seen = now
        # The leader is gone. A background process may still hold the pipe:
        # allow one second for what is in it, then everything is killed.
        if self.pipes and not self.paused and self.kill_sent is None and now - self.exit_seen < 1:
            return False
        if self.kill_sent is None:
            self.kill_sent = now
        # its remaining processes are our children now
        if self.daemon.kill_orphans(self.proc.pid):
            self.complain(now)
            return False
        for _ in range(64):
            if not (self.on_out() | self.on_err()):
                break
        for fd in list(self.pipes):
            self.close_fd(fd)
        self.proc.wait()
        return True

    def complain(self, now):
        if self.stuck(now):
            throttled("stuck:" + self.check.label, "%s: process group %d does not die (uninterruptible I/O?). "
                      "Not starting another one.", self.check.label, self.proc.pid)

    def stuck(self, now):
        return self.kill_sent is not None and now - self.kill_sent > 5

    def terminate(self, now):
        self.term_sent = now
        send_session(self.proc, signal.SIGTERM)

    @property
    def timed_out(self):
        return not self.persistent and self.term_sent is not None and not self.interrupted


def text_rows(data, limit=-1):
    lines = data.decode("utf-8", "replace").split("\n", limit)
    if lines and (not lines[-1] or 0 <= limit < len(lines)):
        lines.pop()                      # nothing, or everything beyond the limit
    return [[escape(line.rstrip("\r"))] for line in lines]


def conninfo_quote(value):
    return "'%s'" % str(value).replace("\\", "\\\\").replace("'", "\\'")


class Session(object):
    """THE psql session of one cluster. There is never a second one.

    States: down -> preflight -> starting -> idle <-> running, and draining (stdin closed,
    waiting for psql to leave on its own).

    psql is not killed when it stops answering: killing the client would leave
    the backend behind, and reconnecting would then add one more. Closing
    stdin makes psql exit as soon as, and only when, the server lets go.
    """

    def __init__(self, daemon, cluster):
        self.daemon, self.cluster = daemon, cluster
        self.state, self.proc = "down", None
        self.queue = collections.deque()
        self.check = None
        self.backoff, self.retry_at = 0.0, 0.0
        self.why = ""
        self.backend = "?"
        self.since = time.monotonic()
        self.seq = 0
        self.connected = False
        self.preflight = None
        ident = "|".join((read_file("/etc/machine-id").strip() or socket.gethostname(),
                          daemon.config.logdir, cluster.name))
        # unique per host, logdir and cluster: it identifies our own leftovers
        digest = hashlib.sha1(ident.encode("utf-8", "replace")).hexdigest()
        self.app = "sysmon_next:%s:%s" % (re.sub(r"\W", "_", cluster.name)[:30], digest[:10])
        # Constant: pg_stat_statements would see a new statement in every run otherwise
        self.null = "nil" + digest[10:26]
        self.killed_at = -1e9

    def submit(self, check):
        self.queue.append(check)

    # -- life cycle -----------------------------------------------------
    def start(self, now):
        cl, cfg = self.cluster, self.daemon.config
        options = [
            ("statement_timeout", int(cfg.statement_timeout * 1000)),
            ("lock_timeout", int(cfg.lock_timeout * 1000)),
            ("idle_in_transaction_session_timeout", 10000),
            ("max_parallel_workers_per_gather", 0), ("jit", "off"), ("work_mem", "4MB"),
            ("standard_conforming_strings", "on"), ("intervalstyle", "postgres"), ("datestyle", "ISO"),
            ("client_min_messages", "error"),          # so anything on stderr is an error
            ("default_transaction_read_only", "on" if cl.read_only else "off")]
        remote = cl.host and not cl.host.startswith("/")
        if remote:
            # Server side: drop our backend soon after the network is gone, or it
            # would linger for hours (Linux default) and keep us from reconnecting
            options += [("tcp_keepalives_idle", 10), ("tcp_keepalives_interval", 5),
                        ("tcp_keepalives_count", 3), ("tcp_user_timeout", 20000)]
        params = [("port", cl.port), ("user", cl.user), ("dbname", cl.database),
                  ("application_name", self.app), ("client_encoding", "UTF8"),
                  ("options", " ".join("-c %s=%s" % o for o in options))]
        if cl.host:
            params.append(("host", cl.host))
        if remote:
            params += [("keepalives_idle", 10), ("keepalives_interval", 5), ("keepalives_count", 3),
                       ("tcp_user_timeout", 20000)]
        # No connect_timeout on purpose: giving up on a half made connection
        # leaves a backend in startup, and retrying would add another.
        conninfo = " ".join("%s=%s" % (k, conninfo_quote(v)) for k, v in params)
        self.nonce = "sm" + os.urandom(12).hex()
        self.out, self.err = bytearray(), bytearray()
        self.cut = False
        self.proc = subprocess.Popen(
            encode_args([cfg.psql, "-X", "-q", "-A", "-t", "-w", "-P", "pager=off", "-d", conninfo]),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, start_new_session=True, env=self.daemon.pg_env, cwd="/")
        # From here on there is a psql: whatever fails, it must be drained and reaped
        self.state, self.since, self.started = "starting", now, now
        self.connected, self.done = False, 0
        self.why, self.backend = "", "?"
        self.open_fds = {}
        self.out_fd, self.err_fd = self.proc.stdout.fileno(), self.proc.stderr.fileno()
        try:
            for pipe, fn in ((self.proc.stdout, self.on_out), (self.proc.stderr, self.on_err)):
                set_nonblocking(pipe.fileno())
                self.daemon.selector.register(pipe.fileno(), selectors.EVENT_READ, fn)
                self.open_fds[pipe.fileno()] = pipe
            set_nonblocking(self.proc.stdin.fileno())
        except Exception as exc:
            self.why = "cannot set up the pipes of psql: %s" % exc
            self.drain()
            for fd in list(self.open_fds):
                self.close_fd(fd)
            self.proc.stdout.close()
            self.proc.stderr.close()
            return
        self.send(
            # One of ours already there (stuck leftover of a previous daemon)?
            "SELECT '%s:S:' || pg_backend_pid() || ':' || current_setting('server_version_num') || ':' || (SELECT count(*) FROM pg_stat_activity"
            " WHERE application_name = current_setting('application_name')"
            " AND usename = current_user AND pid <> pg_backend_pid());\n" % self.nonce)

    def send(self, text):
        data = text.encode("utf-8")
        try:
            if os.write(self.proc.stdin.fileno(), data) == len(data):
                return
            self.why = "psql does not read its input"
        except OSError as exc:
            self.why = self.why or "cannot talk to psql: %s" % exc
        self.drain()

    def drain(self):
        if self.state not in ("draining", "down"):
            self.state, self.since = "draining", time.monotonic()
            try:
                self.proc.stdin.close()
            except OSError:
                pass

    def close_fd(self, fd):
        pipe = self.open_fds.pop(fd, None)
        if pipe is not None:
            self.daemon.selector.unregister(fd)
            pipe.close()

    # -- input ----------------------------------------------------------
    def on_err(self):
        fd = self.err_fd
        if fd not in self.open_fds:
            return
        data = read_some(fd)
        if data:
            self.err += data[:max(0, 8192 - len(self.err))]
        elif data == b"":
            self.close_fd(fd)

    def on_out(self):
        fd = self.out_fd
        if fd not in self.open_fds:
            return
        data = read_some(fd)
        if data is None:
            return
        if not data:
            self.close_fd(fd)
            return
        if self.state == "draining" and self.check is None:
            return                         # late answer of an expired query
        self.out += data
        self.scan()

    def scan(self):
        tag = ("%s:%s:" % (self.nonce, "S" if self.state == "starting" else "E%d" % self.seq)).encode()
        # only the tail can hold the end marker; it is the last thing psql prints
        base = max(0, len(self.out) - 65536 - 256)
        pos = self.out.find(tag, base)
        while pos > 0 and self.out[pos - 1:pos] != b"\n":
            pos = self.out.find(tag, pos + 1)
        end = self.out.find(b"\n", pos) if pos >= 0 else -1
        if end < 0:
            limit = self.daemon.config.max_output
            if len(self.out) > limit + 131072:
                # keep the head (data) and the tail (marker may be split)
                self.cut = True
                del self.out[limit:len(self.out) - 256]
            return
        answer = bytes(self.out[pos + len(tag):end]).decode("ascii", "replace")
        body = bytes(self.out[:pos])
        self.out = bytearray()
        if self.state == "starting":
            self.on_started(answer)
        elif self.check is not None:
            check = self.check
            try:
                self.read_errors()
                self.on_answer(body, answer)
            except Exception as exc:
                self.daemon.internal_error()
                self.daemon.release(check, exc)

    def read_errors(self):
        while self.err_fd in self.open_fds:
            before = len(self.err)
            self.on_err()
            if len(self.err) == before:
                break

    def take_errors(self):
        text = " ".join(bytes(self.err).decode("utf-8", "replace").split())
        self.err = bytearray()
        return text[:500]

    def on_started(self, answer):
        self.backend, version, others = answer.split(":")
        self.version = int(version)
        self.connected = True
        try:
            exe = os.path.basename(os.readlink("/proc/%d/exe" % self.proc.pid))
        except OSError:
            exe = "psql"
        if "psql" not in exe:
            # the watchdog would end the wrapper and not psql
            self.why = "[postgres] psql starts %s: it must be psql itself, or a script that execs it" % exe
            self.drain()
            return
        if int(others):
            self.why = "%s session(s) named %s already on the server; not adding another" % (others, self.app)
            self.drain()
            return
        LOG.info("cluster %s: connected (backend %s)", self.cluster.name, self.backend)
        self.backoff = 0.0
        self.err = bytearray()
        self.state, self.since = "idle", time.monotonic()

    def run_next(self, now):
        check = self.check = self.queue.popleft()
        self.seq += 1
        self.ts, self.run_started = time.time(), now
        self.run = self.daemon.run_id(self.ts)
        self.out, self.err = bytearray(), bytearray()
        self.cut = False
        self.state, self.since = "running", now
        # DISCARD ALL brings back the settings of the connection whatever the
        # previous check did to them, and drops its temp tables and advisory locks
        text = "DISCARD ALL;\n"
        if (check.statement_timeout, check.lock_timeout) != \
                (self.daemon.config.statement_timeout, self.daemon.config.lock_timeout):
            text += "SET statement_timeout = %d; SET lock_timeout = %d;\n" % (
                int(check.statement_timeout * 1000), int(check.lock_timeout * 1000))
        if self.version >= 140000:
            # let the server notice by itself that we are gone
            text += "SET client_connection_check_interval = 2000; SET idle_session_timeout = 0;\n"
        self.send("%sCOPY (\n%s\n) TO STDOUT WITH (FORMAT csv, HEADER true, NULL '%s');\n"
                  "SELECT '%s:E%d:' || :'SQLSTATE';\n" % (text, check.body, self.null, self.nonce, self.seq))

    def on_answer(self, body, sqlstate):
        check, self.check = self.check, None
        if self.state == "running":
            self.state, self.since = "idle", time.monotonic()
        check.crashes = 0
        self.done += 1
        rows, columns, errors = [], None, []
        # psql leaves SQLSTATE empty when a COPY fails half way: check both
        complaint = self.take_errors()
        if sqlstate != "00000" or complaint:
            errors.append(("SQLSTATE %s " % sqlstate if sqlstate not in ("", "00000") else "") + complaint)
        else:
            if self.cut or len(body) > self.daemon.config.max_output:
                errors.append("output larger than max_output or max_rows: truncated")
                body = body[:min(len(body), self.daemon.config.max_output)]
            try:
                parsed = csv.reader(io.StringIO(body.decode("utf-8", "replace"), newline=""))
                for row in parsed:
                    if columns is None:
                        columns = tuple(row)
                    elif len(rows) > self.daemon.config.max_rows:
                        errors.append("output larger than max_output or max_rows: truncated")
                        break
                    else:
                        rows.append(["\\N" if v == self.null else escape(v) for v in row])
            except csv.Error as exc:
                errors.append("cannot parse psql output: %s" % exc)
            if errors and rows:
                rows.pop()                          # probably incomplete
        self.daemon.finished(check, self.ts, self.run, self.run_started, columns, rows, errors)

    # -- housekeeping ---------------------------------------------------
    def tick(self, now):
        cfg = self.daemon.config
        if self.state == "down":
            if self.queue and now >= self.retry_at and not self.daemon.stopping:
                self.begin_preflight()
            return
        if self.state == "preflight":
            if self.preflight and not self.daemon.stopping:
                reason = self.preflight.pop()
                self.state = "down"
                if reason:
                    self.failed(now, reason)
                    return
                try:
                    self.start(now)
                except Exception as exc:         # nothing was started
                    self.state = "down"
                    self.failed(now, "cannot start psql: %s" % exc)
            elif not self.preflight and now - self.since > 10:
                throttled("preflight:" + self.cluster.name, "cluster %s: looking for leftovers in /proc hangs "
                          "since %.0fs, not connecting", self.cluster.name, now - self.since)
                self.fail_queue("looking for leftovers in /proc hangs")
            return
        if not self.open_fds or has_exited(self.proc):
            self.reap(now)
            return
        age = now - self.since
        if self.state == "starting" and age > 10:
            self.give_up(now, "connection is not established after %.0fs" % age)
        elif self.state == "running" and \
                age > self.check.statement_timeout + cfg.answer_grace:
            self.give_up(now, "no answer %.1fs after start, statement_timeout did not help" % age)
        elif self.state == "draining":
            if age > 5:
                throttled("drain:" + self.cluster.name,
                          "cluster %s: session stuck for %.0fs (psql pid %d, backend %s). Waiting for it; "
                          "no other connection will be opened. %s",
                          self.cluster.name, age, self.proc.pid, self.backend, self.why)
                self.fail_queue("session is stuck: " + self.why)
                # A psql that is itself stopped or hung does not read what the server
                # sends, and the backend cannot even be cancelled: end psql. One that
                # merely waits for the server is left alone.
                if self.connected and now - self.killed_at > 5 and \
                        (proc_stat(self.proc.pid) or "?")[0] in ("T", "t", "D"):
                    self.killed_at = now
                    LOG.warning("cluster %s: psql %d is stopped or hung, killing it", self.cluster.name, self.proc.pid)
                    send(self.proc.pid, signal.SIGKILL)
        elif self.state == "idle":
            if now - self.started > cfg.session_max_age and self.done:
                self.why = "recycled"
                self.drain()
            elif self.queue and not self.daemon.stopping:
                self.run_next(now)

    def begin_preflight(self):
        """Look for leftovers in /proc before connecting. In a thread, because
        reading a process' command line can block."""
        self.state, self.since, self.preflight = "preflight", time.monotonic(), []
        local = not self.cluster.host or self.cluster.host.startswith("/")
        thread = threading.Thread(target=find_leftovers, name="preflight", args=(
            self.preflight, self.app, local, self.cluster.user, self.cluster.database,
            os.path.basename(self.daemon.config.psql)[:15]))
        thread.daemon = True
        try:
            thread.start()
        except RuntimeError as exc:
            self.state = "down"
            self.failed(time.monotonic(), "cannot start a thread: %s" % exc)

    def give_up(self, now, reason):
        self.why = reason
        LOG.warning("cluster %s: %s; will not reconnect before this session is gone",
                    self.cluster.name, reason)
        self.drain()
        self.fail_current(reason)

    def fail_current(self, reason):
        if self.check is not None:
            check, self.check = self.check, None
            self.daemon.finished(check, self.ts, self.run, self.run_started, None, [], [reason])

    def fail_queue(self, reason):
        while self.queue:
            check, ts = self.queue.popleft(), time.time()
            self.daemon.finished(check, ts, self.daemon.run_id(ts), time.monotonic(), None, [],
                                 ["not run: " + reason], skipped=True)

    def reap(self, now):
        for _ in range(64):                         # what is left in the pipes, bounded
            if not self.open_fds:
                break
            for fd in list(self.open_fds):
                (self.on_out if fd == self.out_fd else self.on_err)()
        if not has_exited(self.proc):
            self.drain()
            return
        for fd in list(self.open_fds):
            self.close_fd(fd)
        self.drain()
        code = self.proc.wait()
        reason = self.take_errors() or self.why or "psql exited with status %d" % code
        recycled = self.why == "recycled" and self.check is None
        self.state, self.proc = "down", None
        if recycled or (self.daemon.stopping and self.check is None):
            self.retry_at = now
            return
        check = self.check
        self.fail_current("connection lost: " + reason)
        # "terminating connection" is a shutdown or another backend's crash
        if check is not None and code > 0 and "server closed the connection" in reason \
                and "terminating connection" not in reason:
            check.crashes += 1
            if check.crashes >= 2:
                # A crash of some other backend looks the same from here, so not for ever
                pause = min(86400, 3600 * 2 ** min(check.crashes - 2, 5))
                check.disabled_until = now + pause
                LOG.error("%s: the server closed the connection %d times in a row while running it (does it crash "
                          "its backend?). DISABLED for %dh", check.label, check.crashes, pause // 3600)
                self.daemon.note(check, "DISABLED for %dh: its backend seems to crash" % (pause // 3600))
        # A psql killed while connecting may have left a backend in startup,
        # which cannot be seen from SQL: do not add to it quickly
        self.failed(now, reason, 300.0 if code < 0 and not self.connected else 0.0)

    def failed(self, now, reason, minimum=0.0):
        self.backoff = min(60.0, max(5.0, self.backoff * 2))
        wait = max(self.backoff, minimum)
        self.retry_at = now + wait
        LOG.warning("cluster %s: %s; next attempt in %.0fs", self.cluster.name, reason, wait)
        self.fail_queue(reason)

    def shutdown(self):
        if self.proc is not None:
            self.drain()


def find_leftovers(result, app, local, user, database, psql):
    """Appends '' or the reason not to connect now."""
    reason = ""
    try:
        uptime = time.clock_gettime(7)               # CLOCK_BOOTTIME; /proc/uptime is faked in LXC
        tick = os.sysconf("SC_CLK_TCK")
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            comm = read_proc(pid, "comm").strip()
            if "psql" in comm or comm == psql:
                if app in read_proc(pid, "cmdline") and (proc_stat(pid) or "Z")[0] != "Z":
                    reason = "psql %s of a previous (or another) daemon is still there (stuck, or still connecting)" % pid
                    break
            elif local and "postgres" in comm:
                title = read_proc(pid, "cmdline").replace("\0", " ").strip()
                if re.match(r"^postgres: (.*: )?%s %s \[local\] (startup|authentication)"
                            % (re.escape(user), re.escape(database)), title):
                    st = proc_stat(pid)
                    if st and uptime - float(st[3]) / tick > 5:
                        reason = "backend %s is blocked in startup, not adding another" % pid
                        break
    except Exception as exc:
        LOG.warning("cannot look for leftovers: %s: %s", type(exc).__name__, exc)
    result.append(reason)


# --------------------------------------------------------------------------
# Watchdog: a separate process that only reads a pipe and /proc
# --------------------------------------------------------------------------
class Watchdog(object):
    """Daemon side. Sends 'psql pids | command pids' twice a second."""

    def __init__(self):
        self.proc, self.last, self.retry = None, 0.0, 0.0

    def start(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-I", "-S", os.path.abspath(__file__), "--watchdog"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, bufsize=0, start_new_session=True, cwd="/")
        set_nonblocking(self.proc.stdin.fileno())

    def beat(self, now, psql, commands):
        if self.proc is None or has_exited(self.proc):
            if now < self.retry:
                return
            self.retry = now + 10
            if self.proc is not None:
                LOG.warning("watchdog died, starting it again")
                self.proc.stdin.close()
                self.proc.wait()
            self.start()
        if now - self.last >= 0.5:
            self.last = now
            line = "%s|%s\n" % (" ".join(map(str, psql)), " ".join(map(str, commands)))
            try:
                os.write(self.proc.stdin.fileno(), line.encode("ascii"))
            except OSError:
                pass

    def stop(self):
        if self.proc is not None:
            try:
                os.write(self.proc.stdin.fileno(), b"bye\n")
            except OSError:
                pass
            self.proc.stdin.close()


def watchdog_main():
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, signal.SIG_IGN)           # leaves when the daemon does
    selector = selectors.DefaultSelector()
    selector.register(0, selectors.EVENT_READ)
    known, psql, commands, buf, last, bye = {}, set(), set(), b"", time.monotonic(), False

    def kill(pids):
        for pid in pids:
            if known.get(pid):
                send(pid, signal.SIGKILL, known[pid])        # never a recycled pid

    while True:
        if selector.select(1):
            data = os.read(0, 65536)
            if not data:
                break
            last = time.monotonic()
            buf += data
            lines = buf.split(b"\n")
            buf = lines.pop()
            for line in lines:
                if line == b"bye":
                    bye = True
                elif b"|" in line:
                    a, b = line.decode("ascii").split("|")
                    psql, commands = set(map(int, a.split())), set(map(int, b.split()))
                    fresh = {}
                    for pid in psql | commands:
                        st = proc_stat(pid) if pid not in known else None
                        fresh[pid] = known.get(pid) or (st and st[3])
                    known = fresh
        elif time.monotonic() - last > STALL_LIMIT:
            # The daemon does not consume query output any more. A backend that is
            # blocked on sending cannot be cancelled; closing its client frees it.
            kill(psql)
            psql = set()
    if not bye:                                      # the daemon was killed
        sessions = set(pid for pid in commands if known.get(pid))
        kill(commands)
        for name in os.listdir("/proc"):             # and what they started
            st = proc_stat(name) if name.isdigit() else None
            if st and st[2] in sessions and int(st[3]) >= int(known[st[2]]):
                send(int(name), signal.SIGKILL, st[3])


# --------------------------------------------------------------------------
# Daemon
# --------------------------------------------------------------------------
class Daemon(object):
    def __init__(self, config, once=False):
        self.config, self.once = config, once
        self.selector = selectors.DefaultSelector()
        self.writer = Writer(config)
        self.maintenance = [Maintenance(config, sink) for sink in self.writer.sinks.values()]
        self.strays = {}
        self.inherited = set(direct_children())
        self.housekeeping = 0.0
        self.commands = []
        self.waiting = collections.deque()
        self.sessions = collections.OrderedDict()
        self.stopping = False
        self.counter = 0
        self.results = {}
        self.internal_errors = collections.deque(maxlen=20)
        base = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        base.update(LC_ALL="C", S_TIME_FORMAT="ISO")
        base.update(config.env)
        local = dict(base)
        for key in ("PGOPTIONS", "PGSERVICE", "PGAPPNAME", "PGCONNECT_TIMEOUT", "PGHOST", "PGHOSTADDR",
                    "PGPORT", "PGUSER", "PGDATABASE", "PGCLIENTENCODING", "PSQLRC"):
            local.pop(key, None)
        # encoded by hand: before Python 3.7 a C locale means ASCII
        self.command_env, self.pg_env = [
            dict(zip(encode_args(env), encode_args(env.values()))) for env in (base, local)]
        self.marker = "SYSMON_COMMAND=" + os.urandom(16).hex()
        key, _, value = self.marker.partition("=")
        self.command_env[key.encode()] = value.encode()          # not in pg_env: psql is never an orphan to kill
        self.watchdog = Watchdog()
        for chk in config.checks:
            if chk.cluster is not None and chk.cluster.name not in self.sessions:
                self.sessions[chk.cluster.name] = Session(self, chk.cluster)

    def run_id(self, ts):
        self.counter += 1
        return "%d.%d" % (ts, self.counter)

    # -- checks ---------------------------------------------------------
    def launch(self, check, now):
        check.busy = True
        if check.type == "query":
            self.sessions[check.cluster.name].submit(check)
        elif check.type == "file" and \
                re.match(r"^/proc/(loadavg|meminfo|stat|vmstat|diskstats|uptime)$", check.body):
            ts = time.time()
            run, rows, errors = self.run_id(ts), [], []
            try:
                with open(check.body, "rb") as fh:
                    rows = text_rows(fh.read(self.config.max_output), self.config.max_rows)
            except OSError as exc:
                errors.append(str(exc))
            self.finished(check, ts, run, now, ("line",), rows, errors)
        else:
            self.waiting.append(check)

    def argv(self, check):
        if check.type == "file":            # may be on a hanging filesystem: not in this process
            return ["cat", "--", check.body]
        if check.type == "pg_processes":
            return [sys.executable, "-I", "-S", os.path.abspath(__file__), "--pg-processes"]
        return ["/bin/sh", "-c", check.body]

    def start_command(self, check):
        try:
            self.commands.append(Command(self, check, self.argv(check)))
        except Exception as exc:
            ts = time.time()
            self.finished(check, ts, self.run_id(ts), time.monotonic(), None, [], ["cannot start: %s" % exc])

    def command_done(self, cmd, now):
        check, errors, columns = cmd.check, [], ("line",)
        code = cmd.proc.returncode
        if code or cmd.timed_out or cmd.interrupted:
            del cmd.buf[cmd.buf.rfind(b"\n") + 1:]       # killed in the middle of a line
        if cmd.persistent:
            cmd.flush_lines(final=True)
            if not self.stopping:
                errors += cmd.take_errors()
                errors.append("exited with status %d, will be restarted" % code)
                if now - cmd.started > 300:
                    check.fails = 0
            self.finished(check, time.time(), cmd.run, cmd.started, columns, [], errors, count=cmd.lines)
            return
        rows = text_rows(bytes(cmd.buf), self.config.max_rows + 1)
        if cmd.interrupted:
            errors.append("interrupted by shutdown")
        elif cmd.timed_out:
            errors.append("killed after timeout of %gs" % check.timeout)
        elif code:
            errors.append("exit status %d" % code)
        if cmd.truncated or len(rows) > self.config.max_rows:
            errors.append("output larger than max_output or max_rows: truncated")
            rows = rows[:-1]
        failed = bool(errors)
        errors += cmd.take_errors()
        if check.type == "pg_processes" and not failed:
            rows = [row[0].split("\\t") for row in rows]
            columns = tuple(rows.pop(0)) if rows else None
        elif check.type == "pg_processes":
            rows, columns = [], None
        self.finished(check, cmd.ts, cmd.run, cmd.started, columns, rows, errors)

    def finished(self, check, ts, run, started, columns, rows, errors, skipped=False, count=None):
        """Every run of every check ends here exactly once."""
        now = time.monotonic()
        check.busy = False
        check.runs += 1
        ok = not errors
        # output came, even if the exit status or stderr complain (df and a stale
        # mount, for example): no reason to look less often
        useful = ok or (bool(rows) and check.type == "command")
        check.fails = 0 if useful else check.fails + (0 if skipped else 1)
        if check.type == "persistent":
            delay = min(300.0, 5.0 * 2 ** min(check.fails - 1, 6)) if check.fails else 5.0
        elif check.fails > 2:
            # A check that keeps failing is retried less and less often
            delay = max(check.interval, min(60.0, check.interval * 2 ** min(check.fails - 2, 5)))
        else:
            delay = check.interval
        grid = check.next_run + delay
        check.next_run = grid if grid > now else now + delay
        # of consecutive skipped runs only the first leaves a line in the check's log
        stored = True
        if not skipped or not check.skip_logged:
            stored = self.writer.write(check.target, check.name, check.meta(), columns, ts, run, rows, errors)
        check.skip_logged = skipped
        if errors:
            throttled("check:%s" % check.label, "%s: %s", check.label, "; ".join(errors))
        self.writer.write(
            SELF_TARGET, "runs", "# check=runs target=%s type=internal format=columns interval=0" % SELF_TARGET,
            ("target", "check", "status", "duration_ms", "rows", "dropped_writes"), ts, run,
            [[check.target, check.name, "ok" if ok else "skipped" if skipped else "error",
              "%.1f" % ((now - started) * 1000), str(len(rows) if count is None else count),
              str(self.writer.dropped)]])
        self.results[check.label] = (ok and stored, len(rows),
                                     "; ".join(errors) or ("" if stored else "could not be logged"))

    def note(self, check, message):
        ts = time.time()
        self.writer.write(check.target, check.name, check.meta(), None, ts, self.run_id(ts), [], [message])

    # -- orphans --------------------------------------------------------
    def kill_orphans(self, session_id=None):
        """Kills processes our commands left behind (they are our children, see
        become_subreaper). Returns how many of the given session are still alive."""
        known = set(c.proc.pid for c in self.commands)
        known.update(s.proc.pid for s in self.sessions.values() if s.proc is not None)
        if self.watchdog.proc is not None:
            known.add(self.watchdog.proc.pid)
        running = set(c.proc.pid for c in self.commands if c.exit_seen is None)
        alive, strays = 0, {}
        for pid in direct_children():
            if pid in known:
                continue
            st = proc_stat(pid)
            if st is None or st[0] == "Z":
                try:                     # hidepid also hides zombies
                    gone = os.waitpid(pid, os.WNOHANG)[0] == pid
                except ChildProcessError:
                    gone = True
                if st is not None:
                    if session_id is not None and st[2] == session_id:
                        alive += 1       # its own children are adopted now: look again
                    continue
                if gone:
                    continue
            elif st[2] in running:
                continue                 # background job of a command that is still running
            # Killed is only what is in a session whose leader (a zombie we hold) is
            # ours. We may have other children: inherited ones, or everybody's orphans
            # when we are pid 1. Those, and what left its session, are never touched.
            elif st[2] in known:
                if not is_postgres(pid):
                    send(pid, signal.SIGKILL, st[3])
                    if session_id is not None and st[2] == session_id:
                        alive += 1
                continue
            if pid in self.strays:
                strays[pid] = self.strays[pid]
            elif pid not in self.inherited and is_stray(pid, self.marker):
                strays[pid] = time.monotonic()
                throttled("stray", "process %d was left behind by a check in a session of its own: not touched, "
                          "but it counts (no command is started while there are 8)", pid)
        self.strays = strays
        return alive

    def release(self, check, exc):
        """Processing a result failed: the check must not stay busy for ever."""
        if check is not None and check.busy:
            check.busy = False
            check.fails += 1
            check.next_run = time.monotonic() + max(check.interval, 5.0)
            LOG.error("%s: result lost: %s: %s", check.label, type(exc).__name__, exc)
            self.results[check.label] = (False, 0, "result lost: %s" % type(exc).__name__)
            check.runs += 1
            self.note(check, "result lost: %s: %s" % (type(exc).__name__, exc))

    # -- main loop ------------------------------------------------------
    def loop_once(self):
        now = time.monotonic()
        for check in self.config.checks:
            if not check.busy and now >= check.next_run and not self.stopping and now >= check.disabled_until:
                if self.once and check.runs:
                    continue
                self.launch(check, now)
        running = sum(1 for c in self.commands if not c.persistent and not c.stuck(now))
        stuck = sum(1 for c in self.commands if c.stuck(now)) + \
            sum(1 for since in self.strays.values() if now - since > 5)
        if stuck >= 8 and self.waiting:
            throttled("toomany", "%d unkillable processes: not starting any command", stuck)
        else:
            for _ in range(len(self.waiting)):
                check = self.waiting.popleft()
                if check.type == "persistent":
                    self.start_command(check)
                elif running < self.config.max_parallel:
                    running += 1
                    self.start_command(check)
                else:
                    self.waiting.append(check)
        if now - self.housekeeping >= 1:
            self.housekeeping = now
            self.kill_orphans()
        # Sessions that are still connecting are left alone: killing those leaves
        # backends in startup. Once connected, a dead psql ends its backend.
        self.watchdog.beat(
            now, [x.proc.pid for x in self.sessions.values() if x.proc is not None and x.connected],
            [c.proc.pid for c in self.commands if c.exit_seen is None])
        # a bug triggered by one of them must not stop the others
        for session in self.sessions.values():
            try:
                session.tick(now)
            except Exception:
                self.internal_error()
        for cmd in list(self.commands):
            try:
                done = cmd.tick(now)
            except Exception:
                self.internal_error()
                continue
            if done:
                self.commands.remove(cmd)
                try:
                    self.command_done(cmd, now)
                except Exception as exc:
                    self.internal_error()
                    self.release(cmd.check, exc)

        busy = any(c for c in self.commands if not c.persistent) or \
            any(s.state in ("preflight", "starting", "running", "draining") for s in self.sessions.values())
        nearest = min([max(c.next_run, c.disabled_until) for c in self.config.checks if not c.busy] or [now + 1])
        ready_sessions = any(s.queue and s.state == "idle" for s in self.sessions.values())
        # 10ms floor: whatever goes wrong, this loop cannot spin
        timeout = 0.01 if ready_sessions else max(0.01, min(0.1 if busy else 1.0, nearest - now))
        spun = time.monotonic()
        events = self.selector.select(timeout)
        for key, _ in events:
            if key.fd in self.selector.get_map():
                key.data()
        if events and time.monotonic() - spun < 0.002:
            time.sleep(0.002)

    def run(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self.on_signal)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        become_subreaper()
        self.writer.start()
        # spread the first runs, so that checks do not all fire at the same instant
        now = time.monotonic()
        for i, check in enumerate(self.config.checks):
            check.next_run = now + (0 if self.once else (i * 0.25) % 5)
        if not self.once:
            for thread in self.maintenance:
                thread.start()
        LOG.info("started, %d checks, %d clusters, pid %d",
                 len(self.config.checks), len(self.sessions), os.getpid())
        deadline = now + 30
        while not self.stopping:
            try:
                self.loop_once()
            except Exception:
                self.internal_error()
            seen = self.internal_errors
            if len(seen) == 20 and seen[-1] - seen[0] < 120:
                LOG.error("too many internal errors, exiting")
                self.shutdown()
                return 1
            if self.once and (time.monotonic() > deadline or all(
                    c.runs or c.type == "persistent" for c in self.config.checks)):
                break
        self.shutdown()
        return 0

    def internal_error(self):
        """A bug must neither kill collection at once nor spin forever."""
        LOG.exception("internal error")
        self.internal_errors.append(time.monotonic())
        time.sleep(1)

    def on_signal(self, signum, frame):
        self.stopping = True

    def shutdown(self):
        LOG.info("stopping")
        self.stopping = True
        for thread in self.maintenance:
            thread.stop.set()
        for session in self.sessions.values():
            session.shutdown()
        for cmd in self.commands:
            cmd.interrupted = cmd.term_sent is None
            cmd.terminate(time.monotonic())
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline and (
                self.commands or any(s.proc for s in self.sessions.values())):
            now = time.monotonic()
            try:
                self.watchdog.beat(now, [x.proc.pid for x in self.sessions.values() if x.proc is not None
                                         and x.connected], [c.proc.pid for c in self.commands])
                for cmd in list(self.commands):
                    if cmd.tick(now):
                        self.commands.remove(cmd)
                        self.command_done(cmd, now)
                for session in self.sessions.values():
                    if session.proc is not None:
                        session.tick(now)
                for key, _ in self.selector.select(0.05):
                    if key.fd in self.selector.get_map():
                        key.data()
            except Exception:
                self.internal_error()
        for session in self.sessions.values():
            if session.proc is None:
                continue
            if not session.connected:
                # Its stdin is closed: it leaves by itself once connected. Killing it
                # would hide a backend in startup from the next daemon.
                LOG.warning("cluster %s: psql %d is still connecting, left alone",
                            session.cluster.name, session.proc.pid)
                continue
            # SIGINT asks the server to cancel; then leave. A stuck backend is
            # found by the "already on the server" test of the next daemon.
            send(session.proc.pid, signal.SIGINT)
            time.sleep(0.2)
            send(session.proc.pid, signal.SIGKILL)
            LOG.warning("cluster %s: left a stuck session behind (backend %s)",
                        session.cluster.name, session.backend)
        for cmd in self.commands:
            send_session(cmd.proc, signal.SIGKILL)
        self.watchdog.stop()
        self.flushed = self.writer.flush(5)
        LOG.info("stopped")


# --------------------------------------------------------------------------
# pg_processes: what are the PostgreSQL backends of this host doing
# --------------------------------------------------------------------------
# greedy: role, database or cluster_name may contain "[local]" or "(1)" too.
# States never do, except "(aborted)", which is not numeric.
TITLE_RE = re.compile(r"^postgres: .*(?:\[local\]|\S+\(\d+\))(?: (.*))?$")
BACKGROUND_RE = re.compile(
    r"(checkpointer|background writer|walwriter|walreceiver|walsummarizer|logger|archiver|startup|stats collector|"
    r"io worker \d+|autovacuum launcher|autovacuum worker|logical replication|slotsync worker|parallel worker)")


def backend_state(title):
    """'postgres: bob shop 10.1.1.1(5) idle in transaction' -> 'idle in transaction'"""
    title = title.strip()
    m = TITLE_RE.match(title)
    tail = title.rsplit(": ", 1)[-1]
    if not m or (BACKGROUND_RE.match(tail) and "[local]" not in tail and not re.search(r"\(\d+\)", tail)):
        return None                                  # checkpointer, autovacuum, postmaster ...
    state = (m.group(1) or "").strip() or "unknown"
    return re.sub(r"\s+[0-9A-F]+/[0-9A-F]+$", "", state)     # 'streaming 1/AB' -> 'streaming'


def read_proc(*parts, **options):
    return read_file(os.path.join("/proc", *parts), **options)


def read_file(path, limit=65536):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def postmaster_port(pid):
    # readable only when we run as the cluster's owner (or root)
    lines = read_proc(pid, "cwd", "postmaster.pid").split("\n")
    return lines[3].strip() if len(lines) > 3 and lines[0].strip() == pid else "?"


def pg_processes():
    counts, ports = {}, {}
    for pid in os.listdir("/proc"):
        # comm first: unlike cmdline it never waits for the process' memory lock
        if not pid.isdigit() or not re.search(
                "postgres|postmaster", read_proc(pid, "comm")):
            continue
        title = read_proc(pid, "cmdline").replace("\0", " ").strip()
        state = backend_state(title)
        if state is None:
            if not title.startswith("postgres: ") and title:
                port = postmaster_port(pid)
                if port != "?":
                    counts.setdefault(port, {})
            continue
        m = re.search(r"^PPid:\s+(\d+)", read_proc(pid, "status"), re.M)
        parent = m.group(1) if m else "?"
        if parent not in ports:
            ports[parent] = postmaster_port(parent)
        per = counts.setdefault(ports[parent], {})
        per[state] = per.get(state, 0) + 1
    out = ["port\tstate\tcount"]
    for port in sorted(counts) or ["-"]:
        per = counts.get(port, {})
        out.append("%s\tTOTAL\t%d" % (port, sum(per.values())))
        for state in sorted(per):
            out.append("%s\t%s\t%d" % (port, escape(state), per[state]))
    sys.stdout.write("\n".join(out) + "\n")


# --------------------------------------------------------------------------
# Start up
# --------------------------------------------------------------------------
def protect_host(config):
    """Make sure that whatever happens, we are the victim and not the server."""
    try:
        with open("/proc/self/oom_score_adj", "w") as fh:
            fh.write("1000")
    except OSError as exc:
        LOG.warning("cannot set oom_score_adj: %s", exc)
    try:
        os.nice(max(0, config.nice - os.getpriority(os.PRIO_PROCESS, 0)))
    except OSError as exc:
        LOG.warning("cannot set nice: %s", exc)
    try:
        # glibc reserves 64MB of address space per thread otherwise, all of which
        # counts for RLIMIT_AS
        ctypes.CDLL(None).mallopt(-8, 1)             # M_ARENA_MAX
    except (OSError, AttributeError):
        pass
    for what, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_AS, config.max_memory),
                        (resource.RLIMIT_NOFILE, 1024)):
        try:
            soft, hard = resource.getrlimit(what)
            if hard != resource.RLIM_INFINITY:
                value = min(value, hard)
            resource.setrlimit(what, (value, hard))
        except (OSError, ValueError, OverflowError) as exc:
            LOG.warning("cannot set resource limit: %s", exc)


def take_lock(config):
    """Only one daemon per logdir. flock vanishes with the process: no stale pidfiles."""
    if not os.path.isdir(config.logdir):
        raise ConfigError("logdir %s does not exist (create it, owned by the monitoring user)" % config.logdir)
    fds = []
    own = [c.logdir for c in config.clusters.values() if os.path.dirname(c.logdir) != config.logdir]
    for path in [config.logdir] + own:
        try:
            fds.append(os.open(os.path.join(path, ".lock"),
                               os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640))
            fcntl.flock(fds[-1], fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ConfigError("another daemon is already running on %s" % path)
        except OSError as exc:
            if path != config.logdir:            # not mounted, for example: the sink reports it
                LOG.warning("cannot lock %s: %s", path, exc)
                continue
            raise ConfigError("cannot lock %s: %s" % (path, exc))
    return fds


def daemonize():
    if os.fork():
        os._exit(0)
    os.setsid()
    if os.fork():
        os._exit(0)
    null = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(null, fd)
    os.close(null)


def main():
    parser = argparse.ArgumentParser(description="collect system and PostgreSQL data into log files")
    parser.add_argument("config", nargs="?")
    parser.add_argument("-d", "--daemonize", action="store_true", help="detach (not needed under systemd)")
    parser.add_argument("-t", "--test-config", action="store_true", help="validate the config and exit")
    parser.add_argument("--once", action="store_true", help="run every periodic check once, report, exit")
    parser.add_argument("--pg-processes", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--watchdog", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    # an inherited SIG_IGN would make the kernel reap our children behind our back
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    if args.watchdog:
        return watchdog_main()
    if args.pg_processes:
        return pg_processes()
    if not args.config:
        parser.error("config file is required")

    logging.Formatter.converter = time.localtime
    LOG.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    direct = handler
    LOG.addHandler(handler)
    logging.raiseExceptions = False
    os.umask(0o027)
    csv.field_size_limit(1 << 26)
    try:
        config = Config(args.config)
        if args.test_config:
            print("%s: ok, %d checks on %d targets" % (
                args.config, len(config.checks), len(set(c.target for c in config.checks))))
            path = config.env.get("PATH", os.environ.get("PATH", ""))
            if config.clusters and not shutil.which(config.psql, path=path):
                config.warnings.append("psql (%s) not found" % config.psql)
            for root in [config.logdir] + [c.logdir for c in config.clusters.values()
                                           if os.path.dirname(c.logdir) != config.logdir]:
                if not os.path.isdir(root):
                    config.warnings.append("log directory %s does not exist" % root)
            for warning in config.warnings:
                print("warning: " + warning)
            return 0
        if os.geteuid() == 0:
            LOG.warning("running as root is not needed and not recommended")
        lock = take_lock(config)
    except ConfigError as exc:
        LOG.error("%s", exc)
        return 2
    if args.daemonize and not args.once:
        daemonize()
        LOG.removeHandler(handler)
        direct = logging.handlers.RotatingFileHandler(
            os.path.join(config.logdir, "system_monitoring_next.log"), maxBytes=5 << 20, backupCount=2)
        direct.setFormatter(formatter)
        LOG.addHandler(direct)
    for warning in config.warnings:
        LOG.warning("%s", warning)
    if not args.once:
        try:
            fd = os.open(config.pidfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
            os.write(fd, b"%d\n" % os.getpid())
            os.close(fd)
        except OSError as exc:
            LOG.error("cannot write pidfile: %s", exc)
            return 2
    protect_host(config)
    threading.stack_size(512 * 1024)
    LOG.removeHandler(direct)
    queued = QueuedLog(direct)
    LOG.addHandler(queued)
    daemon = Daemon(config, once=args.once)
    try:
        code = daemon.run()
    finally:
        if not args.once:
            Maintenance.unlink(config.pidfile)
        queued.wait(2)
    if args.once:
        for check in config.checks:
            ok, rows, why = daemon.results.get(
                check.label, (check.type == "persistent", 0, "still running"))
            print("%-5s %-40s %6d rows  %s" % ("ok" if ok else "FAIL", check.label, rows, why))
            code = code or (0 if ok else 1)
        if daemon.writer.dropped or not daemon.flushed:
            print("FAIL  some results could not be logged, see the messages above")
            code = 1
    for fd in lock:
        os.close(fd)
    sys.stdout.flush()
    # a thread stuck on a hung filesystem must not keep us from leaving
    os._exit(code)


if __name__ == "__main__":
    sys.exit(main())
