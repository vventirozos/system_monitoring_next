"""python3 -m unittest discover tests"""
import contextlib
import gzip
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.dont_write_bytecode = True
import sysmon_export as ex          # noqa: E402
import system_monitoring_next as sm  # noqa: E402


def run(parser, text, run="1000.1", epoch=1010.0):
    out = []
    for _, _, row in ex.PARSERS[parser]((epoch, "t", run, line) for line in text.strip("\n").split("\n")):
        row.pop("_sysmon_order", None)
        row.pop("_sysmon_group", None)
        out.append(row)
    return out


class Daemon(unittest.TestCase):
    def test_sql(self):
        for good in ("select 1", "select ';', $$;\\$$, $a$ ) $a$, \"x;\"", "select E'it\\'s;'", "select (1) -- (;",
                     "select /* ; */ 1", "select a[1:2], 'x\\'", "select 'it''s'"):
            sm.check_sql(good)
        for bad in ("select 1; drop table x", "select 'a", "select (1", "select 1)", "\\! id",
                    "select $$a", "select 1 as a$b$) ; x (a$b$", "select 1 /*/", "x$E'\\' ; --'", "select /* a", "select \"a"):
            with self.assertRaises(sm.ConfigError, msg=bad):
                sm.check_sql(bad)

    def test_units(self):
        self.assertEqual([sm.parse_duration(x) for x in ("500ms", "2s", "5min", "1h", "2d", "7")],
                         [0.5, 2, 300, 3600, 172800, 7])
        self.assertEqual([sm.parse_size(x) for x in ("2kB", "3MB", "1GiB")], [2048, 3 << 20, 1 << 30])
        self.assertRaises(sm.ConfigError, sm.parse_size, "20")
        for bad in ("", "-1", "1x", "nan"):
            self.assertRaises(sm.ConfigError, sm.parse_duration, bad)

    def test_escape_round_trip(self):
        for value in ("a\tb\nc\\d\re", "\\N", "\\\\t", "", "é\0"):
            self.assertEqual(ex.unescape(sm.escape(value)), value)
            self.assertNotRegex(sm.escape(value), "[\t\n\r\0]")

    def test_backend_state(self):
        for title, state in (
                ("postgres: bob shop [local] idle", "idle"),
                ("postgres: bob shop 10.0.0.1(5432) idle in transaction (aborted)", "idle in transaction (aborted)"),
                ("postgres: c1: bob shop ::1(1) UPDATE waiting", "UPDATE waiting"),
                ("postgres: walsender rep 10.0.0.1(99) streaming 1A/2B3C", "streaming"),
                ("postgres: a [local] b: checkpointer ", None), ("postgres: we(1)ird db [local] idle", "idle"),
                ("postgres: checkpointer ", None), ("postgres: autovacuum worker shop", None),
                ("/usr/bin/postgres -D /x", None)):
            self.assertEqual(sm.backend_state(title), state)

    def test_signals_go_through_one_guarded_place(self):
        with open(sm.__file__) as fh:
            source = fh.read()
        self.assertEqual(source.count("os.kill("), 1)
        for word in ("os.killpg(", ".send_signal(", "proc.kill(", "proc.terminate("):
            self.assertNotIn(word, source)

    def test_rows_limit(self):
        self.assertEqual(sm.text_rows(b"a\nb\nc", 2), [["a"], ["b"]])
        self.assertEqual(sm.text_rows(b"a\nb\n"), [["a"], ["b"]])
        self.assertEqual(sm.text_rows(b""), [])

    def config(self, text):
        fd, path = tempfile.mkstemp()
        os.write(fd, text.encode())
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return sm.Config(path)

    def test_config(self):
        base = "[global]\nlogdir=/tmp/x\n"
        chk = "[check a]\ninterval=5\n"
        cfg = self.config(base + "[vars]\nq=select 1\n[cluster c1]\n[cluster c2]\nport=5433\n" + chk + "query=@q;\n")
        self.assertEqual([(c.target, c.body) for c in cfg.checks], [("c1", "select 1"), ("c2", "select 1")])
        for bad in (chk + "exec=ls\ntypo=1\n", "[check a]\nexec=ls\n", chk + "query=select 1\n", chk + "exec=\n",
                    "[cluster os]\n" + chk + "exec=ls\n",
                    "[cluster c]\nlogdir=/tmp/x/os/sub\n" + chk + "exec=ls\n",
                    "[postgres]\nstatement_timeout=0\n" + chk + "exec=ls\n",
                    "[postgres]\nlock_timeout=0\n" + chk + "exec=ls\n",
                    "[cluster c]\n" + chk + "query=select 1\nstatement_timeout=10min\n",
                    chk + "exec=ls\n" + chk + "exec=ls\n", chk + "exec=ls\nfile=/x\n", "[nope]\n" + chk + "exec=ls\n",
                    "[check  a]\ninterval=5\nexec=ls\n" + chk + "exec=ls\n", chk + "exec=ls\nlock_timeout=1s\n",
                    "[postgres]\nsession_max_age=0\n" + chk + "exec=ls\n",
                    "[retention]\nmin_free_space=0MB\n" + chk + "exec=ls\n",
                    "[retention]\nmax_size_per_target=20\n" + chk + "exec=ls\n",
                    "[global]\npidfile=/x\n" + chk + "exec=ls\n",
                    "[cluster c]\n" + chk + "query=select 1\nclusters=\n",
                    "[cluster c]\n" + chk + "query=select a\n  #>> 'b'\n"):
            with self.assertRaises(sm.ConfigError, msg=bad):
                self.config(base + bad)

    def test_shipped_config(self):
        here = os.path.dirname(os.path.abspath(__file__))
        self.assertEqual(len(sm.Config(os.path.join(here, "..", "config.sample")).checks), 62)


class Export(unittest.TestCase):
    def test_numeric(self):
        for value, want in (("12%", "12"), ("1.5Gi", "1610612736"), ("00:00:01.5", "1.5"), ("-00:00:02", "-2"),
                            ("1 day 00:00:02", "86402"), ("2 days", "172800"), ("1 mon", "2592000"), ("1-00:00:01", "86401"), ("nan%", "nan%"), ("abc", "abc"), ("12", "12"),
                            ("2026-01-01 00:00:00", "2026-01-01 00:00:00"), ("s", "s"), (None, None), ("", "")):
            self.assertEqual(ex.numeric(value), want, value)

    def test_time(self):
        self.assertEqual(ex.parse_ts("2026-11-25T14:00:00.250+0200"), ex.parse_ts("2026-11-25 12:00:00.25Z"))
        self.assertEqual(ex.show_time(0, "2026-11-25 14:00:00 -0330", "iso"), "2026-11-25T14:00:00-03:30")
        self.assertEqual(ex.parse_ts("2026-11-25 14:00:00 +0200"), ex.parse_ts("2026-11-25 12:00:00Z"))
        self.assertRegex(sm.stamp(0), r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [+-]\d{4}$")
        self.assertIsNone(ex.parse_ts("2026-13-01 00:00"))

    def test_parsers(self):
        ps = run("table", "USER PID STARTED COMMAND\nroot 1 Wed Nov 25 10:00:00 2026 sh -c  a  b")
        self.assertEqual(ps, [{"USER": "root", "PID": "1", "STARTED": "Wed Nov 25 10:00:00 2026",
                               "COMMAND": "sh -c  a  b"}])
        df = run("table", "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/a 9 4 5 45% /my data")
        self.assertEqual(df[0]["Mounted_on"], "/my data")
        self.assertEqual(run("kv", "MemTotal:  12 kB\nHugePages: 0"), [{"MemTotal": "12", "HugePages": "0"}])
        self.assertEqual(run("loadavg", "0.1 0.2 0.3 1/575 99")[0]["processes"], "575")
        self.assertEqual(run("free", " total used\nMem: 5 3\nSwap: 1 0")[1], {"kind": "Swap", "total": "1", "used": "0"})
        stat = run("procstat", "cpu 1 2 3 4 5 6 7 8 9 10\ncpu0 1 2 3 4\nctxt 77\nintr 5 1 1")
        self.assertEqual((stat[0]["ctxt"], stat[0]["intr_total"], stat[1]["cpu"]), ("77", "5", "cpu0"))
        io = run("iostat", "Linux 6.1 (h) 01/01/26 _x86_64_ (2 CPU)\n\navg-cpu:  %user %idle\n  1.0 99.0\n\n"
                           "Device r/s w/s\nsda 1.0 2.0\n\n")
        self.assertEqual([r["device"] for r in io], ["avg-cpu", "sda"])
        vm = "procs ---memory---\n r b swpd\n 1 0 5"
        self.assertEqual(run("vmstat", vm), [])
        self.assertEqual(run("vmstat", vm + "\n 1 0 5"), [{"r": "1", "b": "0", "swpd": "5"}])
        # a later file starts with the repeated header, not with the banner
        self.assertEqual(run("vmstat", vm.split("\n", 1)[1] + "\n" + vm), [{"r": "1", "b": "0", "swpd": "5"}] * 2)
        self.assertEqual(run("vmstat", vm.replace("procs", "--procs--")), [])
        self.assertEqual(sorted(run("table", "A A\n1 2")[0].items()), [("A", "1"), ("A_2", "2")])
        mp = run("mpstat", "Linux\n\n10:00:00 CPU %usr %idle\n10:00:05 all 1.0 99.0\nAverage: all 1 99")
        self.assertEqual(mp, [{"CPU": "all", "%usr": "1.0", "%idle": "99.0"}])


HEAD = "# check=c target=main type=query format=columns interval=5\n"


class Pipeline(unittest.TestCase):
    """main() on a small log tree"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        del ex.problems[:]
        ex.warned.clear()

    def put(self, hour, text, check="c", gz=False, day="25", raw=False):
        folder = os.path.join(self.root, "main/2026/11", day)
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, "%s-2026-11-%s-%s.tsv%s" % (check, day, hour, ".gz" if gz else ""))
        data = text if raw else HEAD + text
        with (gzip.open if gz else open)(path, "wb") as fh:
            fh.write(data.encode())
        return path

    def go(self, *args):
        """(exit status, stdout, stderr)"""
        out, err, argv = io.StringIO(newline=""), io.StringIO(), sys.argv
        sys.argv, code = ["x", "-l", self.root] + list(args), 0
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                ex.main()
            code = 1 if ex.problems else 0
        except SystemExit as exc:
            code = exc.code
        finally:
            sys.argv = argv
        return code, out.getvalue(), err.getvalue()

    def rows(self, *args):
        code, out, err = self.go("export", "main", "c", *args)
        self.assertEqual((code, err), (0, ""))
        return out.splitlines()

    @staticmethod
    def line(clock, *values, **kw):
        return "\t".join(["2026-11-25 %s +0000" % clock, kw.get("run", clock)] + list(values)) + "\n"

    def two(self):
        self.put("10", "#ts\trun\ta\tb\n" + self.line("10:00:00", "1", "\\N") + self.line("10:00:05", "2", "x"), gz=True)
        self.put("11", "#ts\trun\ta\tc\n" + self.line("11:00:00", "3", ""))

    def test_union_order_null(self):
        self.two()
        self.assertEqual(self.rows("--null", "~"), [
            "datetime,a,b,c", "2026-11-25 10:00:00 +0000,1,~,~", "2026-11-25 10:00:05 +0000,2,x,~",
            "2026-11-25 11:00:00 +0000,3,~,"])
        self.assertEqual(self.rows("-c", "a", "-w", "b=\\N")[1:], ["2026-11-25 10:00:00 +0000,1", "2026-11-25 11:00:00 +0000,3"])

    def test_bounds(self):
        self.two()
        got = self.rows("--from", "2026-11-25 10:00:05Z", "--to", "2026-11-25 11:00:00Z", "-c", "a")
        self.assertEqual(got, ["datetime,a", "2026-11-25 10:00:05 +0000,2"])
        self.assertEqual(self.go("export", "main", "c", "--from", "2026-11-26", "--to", "2026-11-25")[0], 2)

    def test_file_selection(self):
        self.two()
        old = self.put("10", "#ts\trun\ta\n" + self.line("10:00:00", "9").replace("11-25", "11-20"), day="20")
        files = ex.find_files(os.path.join(self.root, "main"), "c", ex.parse_ts("2026-11-25 09:00Z"), None)
        self.assertNotIn(old, [p for _, p in files])
        self.assertEqual(len(files), 2)
        os.utime(files[0][1], (0, 0))
        files = ex.find_files(os.path.join(self.root, "main"), "c", ex.parse_ts("2026-11-25 09:00Z"), None)
        self.assertEqual(len(files), 1)
        # a clock set back an hour does not hide data
        os.utime(files[0][1], (ex.parse_ts("2026-11-25 08:00Z"),) * 2)
        self.assertEqual(len(ex.find_files(os.path.join(self.root, "main"), "c", ex.parse_ts("2026-11-25 09:00Z"), None)), 1)
        self.put("99", "", check="c")
        self.assertEqual(self.go("list")[0], 0)

    def test_damage_is_loud(self):
        good = "#ts\trun\ta\n" + self.line("10:00:00", "1")
        for bad in ("garbage\n", self.line("10:00:01", "1", "2"), "2026-99-25 10:00:00 +0000\tr\t1\n", "\0\0\n",
                    "#!\tnonsense\n"):
            del ex.problems[:]
            ex.warned.clear()
            self.put("10", good + bad)
            code, out, err = self.go("export", "main", "c")
            self.assertEqual((code, out.count("\n"), err.count("1 lines skipped")), (1, 2, 1), bad)
        self.setUp()
        self.put("10", self.line("10:00:00", "1"))                      # header lost
        self.assertEqual(self.go("export", "main", "c")[0], 1)
        self.setUp()
        self.put("10", good + "2026-11-25 10:00\t\\!torn\n" + self.line("10:00:05", "2") + "2026-11-25 10:0")
        code, out, err = self.go("export", "main", "c")
        self.assertEqual((code, out.count("\n"), "cut short" in err), (0, 3, True))

    def test_damaged_gz_and_output(self):
        path = self.put("10", "#ts\trun\ta\n" + "".join(self.line("10:00:00", str(os.urandom(9))) for _ in range(99)), gz=True)
        with open(path, "r+b") as fh:
            fh.truncate(500)
        self.assertEqual(self.go("export", "main", "c")[0], 1)
        target = os.path.join(self.root, "o.csv")
        self.assertEqual(self.go("export", "main", "c", "-o", target)[0], 2)
        self.assertEqual(os.listdir(self.root), ["main"])

    def test_output_file(self):
        self.two()
        target = os.path.join(self.root, "\u00e9.csv")
        self.assertEqual(self.go("export", "main", "c", "-o", target)[0], 0)
        self.assertEqual(os.stat(target).st_mode & 0o007, 0)
        os.chmod(target, 0o600)
        self.assertEqual(self.go("export", "main", "c", "-o", target)[0], 0)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)

    def test_crash_while_compressing(self):
        text = "#ts\trun\ta\n" + self.line("10:00:00", "1")
        self.put("10", text)
        self.put("10", text, gz=True)
        self.assertEqual(len(self.rows()), 2)
        self.put("10", text + self.line("10:00:05", "2"))               # not the same: both count
        self.assertEqual([x[-1] for x in self.rows()[1:]], ["1", "1", "2"])     # compressed part first

    def test_unreadable_directory(self):
        self.two()
        if os.geteuid():
            folder = os.path.join(self.root, "main/2026/11/25")
            os.chmod(folder, 0)
            self.put("10", "#ts\trun\ta\n" + self.line("10:00:00", "1"), day="24")
            code, _, err = self.go("export", "main", "c")
            os.chmod(folder, 0o700)
            self.assertEqual((code, "cannot be read" in err), (1, True))

    def test_pivot(self):
        head = "#ts\trun\tk\tv\n"
        self.put("10", head + self.line("10:00:00", "a", "1", run="1") + self.line("10:00:00", "b", "2", run="1") +
                 self.line("10:00:00", "a", "3", run="2"))
        self.assertEqual(self.rows("--pivot", "k:v"), ["datetime,a,b", "2026-11-25 10:00:00 +0000,1,2", "2026-11-25 10:00:00 +0000,3,"])
        self.put("10", head + self.line("10:00:00", "a", "1", run="1") + self.line("10:00:00", "a", "1", run="1"))
        self.assertEqual(self.go("export", "main", "c", "--pivot", "k:v")[0], 2)

    def test_columns(self):
        self.put("10", "#ts\trun\tdatetime\tlog_datetime\tx\tx\t_order\n" + self.line("10:00:00", "d", "l", "1", "2", "o\\0"))
        self.assertEqual(self.rows()[0], "log_datetime_2,datetime,log_datetime,x,x_2,_order")
        self.assertEqual(self.rows()[1].split(",")[1:], ["d", "l", "1", "2", "o\\0"])
        got = json.loads(self.rows("-f", "json")[0])
        self.assertEqual((got["log_datetime"], got["log_datetime_2"], got["_order"]), ("l", "2026-11-25 10:00:00 +0000", "o\0"))
        self.assertEqual(self.go("export", "main", "c", "-c", "nope")[0], 2)
        self.assertEqual(self.go("export", "main", "nope")[0], 2)

    def test_errors(self):
        self.put("10", "#!\t2026-11-25 10:00:01 +0200\tr\tbad\\nthing\n")
        self.assertEqual(self.go("errors")[1], "2026-11-25 10:00:01 +0200\tmain\tc\tbad thing\n")
        self.assertEqual(self.go("errors", "main", "nope")[0], 2)

    def test_csv_quoting(self):
        self.put("10", "#ts\trun\ta\n" + self.line("10:00:00", 'q"\\n\\t,'))
        self.assertEqual(self.go("export", "main", "c")[1], 'datetime,a\n2026-11-25 10:00:00 +0000,"q""\n\t,"\n')

    def test_no_endless_line(self):
        self.addCleanup(setattr, ex, "MAX_LINE", ex.MAX_LINE)
        ex.MAX_LINE = 100
        self.put("10", "#ts\trun\ta\n" + self.line("10:00:00", "1") + "\0" * 500)
        self.assertEqual(self.go("export", "main", "c")[0], 1)


if __name__ == "__main__":
    unittest.main()
