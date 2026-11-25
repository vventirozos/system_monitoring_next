# system_monitoring_next

Collects system and PostgreSQL data into plain log files. Python 3.6+ standard
library and `psql` 12+; nothing to install. Linux.

| file | what |
|---|---|
| `system_monitoring_next.py` | the daemon |
| `sysmon_export.py` | reads the logs, exports csv / tsv / json / table |
| `config.sample` | sample config, copy it to `config.cfg`: complete config: the existing checks, the dba views, and more |
| `system_monitoring_next.service` | systemd unit with kernel enforced ceilings |
| `dba_schema.v3.sql` | the dba views some checks use (lock views fixed) |
| `tests/` | unit tests, and fault injection scripts (throwaway container ONLY) |

## Install

As root, from a checkout. Assumes that PostgreSQL runs as OS user `postgres`; for another
user change `User=` and `Group=` in the unit, and the owners below.

Packages, Ubuntu / Debian:

    apt update && apt install -y python3 sysstat procps

Rocky / RHEL:

    dnf install -y python3 sysstat procps-ng

Program, config and log directory (mount `/data` first if it is a filesystem of its own, and
keep logdir a directory on it, not the mount point):

    mkdir -p /opt/system_monitoring_next
    cp system_monitoring_next.py sysmon_export.py /opt/system_monitoring_next/
    chown -R root:root /opt/system_monitoring_next
    chmod 755 /opt/system_monitoring_next /opt/system_monitoring_next/*.py
    cp config.sample /etc/system_monitoring_next.cfg
    chown root:postgres /etc/system_monitoring_next.cfg
    chmod 640 /etc/system_monitoring_next.cfg
    mkdir -p /data/system_monitoring_next_logs
    chown postgres:postgres /data/system_monitoring_next_logs
    chmod 750 /data/system_monitoring_next_logs

Edit `/etc/system_monitoring_next.cfg`: `database`, `port`, `logdir`, and `PATH` (where psql is).

Database objects. The `dba` checks need the schema, the `pgss_*` checks need `pg_stat_statements`
in `shared_preload_libraries` (restart). Running the schema again resets its alert thresholds and
silences. Without them set `enabled = off` on these checks.

    sudo -u postgres psql -d YOUR_DATABASE < dba_schema.v3.sql

Test as the service user. `--once` runs each check once and exits 1 if any fails or cannot be logged:

    cd /
    sudo -u postgres /opt/system_monitoring_next/system_monitoring_next.py -t     /etc/system_monitoring_next.cfg
    sudo -u postgres /opt/system_monitoring_next/system_monitoring_next.py --once /etc/system_monitoring_next.cfg

Start now and at boot (from the checkout again):

    cp system_monitoring_next.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now system_monitoring_next

Rocky / RHEL with SELinux, before starting: `restorecon -R /opt/system_monitoring_next
/etc/systemd/system/system_monitoring_next.service`. The `psi` check has no rows there unless the
kernel is booted with `psi=1`: `grubby --update-kernel=ALL --args="psi=1"` and reboot.

Check:

    systemctl status system_monitoring_next
    journalctl -u system_monitoring_next -n 50 --no-pager
    /opt/system_monitoring_next/sysmon_export.py -l /data/system_monitoring_next_logs list

It does not need PostgreSQL or the log filesystem to be up first: it retries. Config changes need
`systemctl restart system_monitoring_next`; SIGHUP is ignored. One daemon per logdir and per
cluster logdir (enforced). Without systemd: `system_monitoring_next.py -d CONFIG` detaches.

If the unit keeps restarting with status 2, the journal says why. Usually:

| message | fix |
|---|---|
| another daemon is already running | one was started by hand: `pgrep -af system_monitoring_next.py`, then stop it |
| logdir ... does not exist | create or mount it |
| cannot lock ... | `.lock` belongs to another user: fix the owner of the log directory |
| cannot read the config, or it is writable by others | owner and mode as above |

## What it guarantees, and how

| risk | protection |
|---|---|
| connections pile up | one psql session per cluster, reused. If it stops answering its stdin is closed and we wait until it is really gone; psql is not killed and replaced (unless it is itself stopped or hung), because the backend would stay. Before connecting we look in /proc for our own psql and for backends of ours blocked in startup; after connecting, if a session with our application_name is already there, we leave and back off (5s up to 60s). At most: one session, plus a momentary probe |
| our query keeps locks because we do not read its result | a backend blocked on sending ignores statement_timeout. So the main loop does no file I/O (each target has a writer thread; data is dropped when it cannot keep up), and a watchdog process kills psql if the main loop is silent for 5s. A psql that is itself stopped or hung (T or D state) is killed once its query should be over |
| slow query | server side `statement_timeout` / `lock_timeout` (0 is rejected), also active while connecting; `DISCARD ALL` before every query, so a check cannot change them for the next one; no parallel query, no JIT, read only, small work_mem |
| a check that crashes its backend | disabled for 1h (doubling up to 24h) after the second time in a row |
| checks pile up | a check never overlaps itself; missed runs are skipped; failing checks back off (max 60s) |
| hung command | deadline, then TERM/KILL of every process in its session. Never signalled: anything named postgres, anything below one, and anything whose working directory is not `/`, `/proc` or `/sys` (a server runs in its data directory, whatever its binary is called). What leaves its session (`setsid`, `sudo` with a pty) is not touched either: it is reported and counted. While anything of a check cannot be killed (D state, sudo, changed directory) it is not started again; with 8 such processes no command is started until some are gone |
| too many processes | `max_parallel_commands` |
| huge output | `max_output`, `max_rows`; a flooding persistent check is blocked, not read |
| full disk | pauses below `min_free_space` (or 1000 free inodes); `max_file_size` per check and hour; `max_size_per_target` removes the oldest logs of that target |
| memory | RLIMIT_AS (`max_memory`), oom_score_adj 1000: the OOM killer takes us before PostgreSQL |
| cleanup deletes something else | only regular files with our exact name in our exact directory; never follows symlinks; only empty directories are removed; nothing expires for a day after the clock jumps by more than an hour |
| internal bug | isolated per check; never spins; exits after 20 errors in 2 minutes, systemd restarts after 30s |

Good to know:

* Connect directly, not through pgbouncer (startup options are used).
* The persistent session makes `pg_ctl stop -m smart` wait, and blocks
  `DROP DATABASE` of the database it is in. Fast/immediate stop is unaffected.
* While a session is stuck or down, the checks of that cluster are skipped. The
  first skipped run leaves a `#!` line; `_daemon/runs` has all of them. Other
  clusters and system checks continue. Queries of one cluster run one at a time.
* What a command leaves in the background is killed when it ends. **Never start a
  service, above all PostgreSQL, from a check**: it is not signalled, but it would live in
  our cgroup (memory limit) and with our oom_score_adj of 1000.
* A check that changes directory (other than below /proc or /sys) cannot be killed when it
  hangs: use absolute paths instead.
* Do not run the daemon as pid 1 of a container that also runs PostgreSQL: its exit ends
  the container.
* `psql` must be psql itself or a script that execs it.
* Not seen before connecting: our own backends stuck in startup on servers with
  `update_process_title = off`. If psql is killed and the daemon restarted during such a
  hang, each restart can add one.
* If the whole machine or cgroup is frozen while a query sends a large result,
  the watchdog is frozen too: do not freeze this service alone.
* If a filesystem should be mounted but is not, a cluster's own `logdir` is not
  created; the default directories below the global logdir are.
* Passwords: `~/.pgpass` (or `PGPASSFILE` in `[env]`), never in the config.
* As extra insurance use a dedicated role with `pg_monitor` and
  `ALTER ROLE ... CONNECTION LIMIT 3`.
* `max_memory` and `nice` are inherited by the commands it runs.
* Logs contain query texts (pg_stat_activity); files are 0640, directories 0750.

## Configuration

`[section]` / `key = value`. Long queries continue on indented lines. Comments are
lines starting with `#`. `@name` is replaced from `[vars]`. Unknown keys are
errors. Durations: `500ms 2s 5min 1h 2d 1w`; sizes: `500MB 20GB`.

    [global]     logdir, nice (10)
    [env]        environment of commands and psql
    [vars]       NAME = text
    [retention]  compress_after (1h), keep (2d), max_size_per_target (10GB), max_file_size (512MB),
                 min_free_space (2GB)
    [limits]     max_parallel_commands (4), command_timeout (10s), max_output (8MB),
                 max_rows (100000), max_memory (1GB)
    [postgres]   statement_timeout (2s), lock_timeout (200ms), answer_grace (3s),
                 session_max_age (1h), psql (psql)
    [cluster X]  port, host, user, database, logdir (<logdir>/X), read_only (on), enabled
    [check X]    exactly one of
                   query = SQL                      on every cluster, or clusters = a, b
                   exec  = shell command            type = persistent if it never ends
                   file  = /proc/...
                   type  = pg_processes             backends per state and port
                 interval, timeout, statement_timeout, lock_timeout, keep, enabled,
                 format = raw|table|kv|free|loadavg|procstat|iostat|vmstat|mpstat
                          (how the exporter parses raw output; the log keeps it as is)

### Role

The shipped config connects as `postgres`. `pg_monitor` plus the `dba` schema is enough
for all of its checks:

    CREATE ROLE sysmon LOGIN CONNECTION LIMIT 3;
    GRANT pg_monitor TO sysmon;
    GRANT USAGE ON SCHEMA dba TO sysmon;
    GRANT SELECT ON ALL TABLES IN SCHEMA dba TO sysmon;
    ALTER ROLE sysmon SET pg_stat_statements.track = 'none';

and `user = sysmon` in `[cluster]`. With peer authentication the OS user `postgres`
needs a pg_ident.conf map to log in as `sysmon`. The grants on `dba` must be repeated
after re-running dba_schema.v3.sql (or rely on its grants to pg_monitor).

Not carried over from the perl version: per check `env`, `header` (automatic
now), `minwait`, `logduration` (always in `_daemon/runs`), `ignore`, `-s/-t` (use
the exporter). Use `iostat -y` and plain `vmstat` (not `-y`): the exporter
leaves out vmstat's first, since-boot report. `iostat -h` is not supported.

Retention is per file age, always whole hours. `keep` in a check overrides the
global one. `max_size_per_target` wins over any `keep`.

`pg_processes` can tell ports apart only when running as the cluster owner (or
root); otherwise the port is `?`.

## Logs

`<logdir>/<target>/YYYY/MM/DD/<check>-YYYY-MM-DD-HH.tsv[.gz]`, target = `os`,
a cluster name, or `_daemon`. Tab separated, one record per line:

    # check=conn_count target=main type=query format=columns interval=5
    #ts	run	application_name	client_addr	count
    2026-11-25 13:02:03 +0000	1795611723.27	pgbench	\N	4
    #!	2026-11-25 13:02:08 +0000	1795611728.31	ERROR: canceling statement due to lock timeout

Lines of one run share `run` (start epoch, counter). `\N` is NULL; tab, newline
and backslash are escaped as in COPY. `#!` is a failed run. The header is
repeated when columns change. `_daemon/runs` has status and duration of every
run: monitor the monitor with it.

## Export

    export SYSMON_LOGDIR=/data/system_monitoring_next_logs
    ./sysmon_export.py list
    ./sysmon_export.py errors main --last 1d
    ./sysmon_export.py export os loadavg --last 2h
    ./sysmon_export.py export os iostat -w device=sda -c r/s,w/s,%util --from '2026-11-25 10:00' --to '2026-11-25 11:00'
    ./sysmon_export.py export os pg_processes -w port=5432 --pivot state:count -o states.csv
    ./sysmon_export.py export main full_activity -n x_age,q_age -f json
    ./sysmon_export.py export /data2/monitoring_main conn_count -f table     # cluster with its own logdir

First column is always the time of the record, `datetime` (`log_datetime` if the check has a
column of that name, `log_datetime_2` if it has both), as in the log: `2026-11-25 13:02:03 +0000`. `--time iso|plain|utc|epoch`
changes it. `-n col1,col2` (or `-n all`) turns intervals into seconds, `1.5Gi`
into bytes, `12%` into 12. Duplicate column names become `x`, `x_2`. An unknown
column is an error (exit 2). Damaged logs give a warning and exit 1; with `-o` exit 2 and no file.
Lines cut short by a crash only give a warning. `--pivot` fails when a key appears twice in a run.
`-w col='\N'` selects NULL. `--from`/`--to` without offset are in the time zone of your shell.
`-f tsv` and `table` turn white space inside values into one space; csv and json keep it.
`-n all` also converts text that looks like a size (`10M`): name the columns. Counters are exported as they are (no rates).
NULL is empty unless `--null TEXT`.
`list` and `errors` without target cover the global logdir; give the path for a cluster with
its own logdir. On RHEL 8 (sysstat 11.7) the first avg-cpu row after a start of iostat is all zeros.

## License

PostgreSQL License, see [LICENSE](LICENSE).
