# Regression tests for the findings of the independent review. Run as postgres
# after setup.sh; /frozen is a loop filesystem made by the caller.
export PATH=/usr/lib/postgresql/17/bin:$PATH; umask 027
A="python3 /app/tests/faults/low.py"; M="psql -XAtq demo_production"
say(){ echo; echo "=== $*"; }
mk(){ chmod -R u+rwX /tmp/rl 2>/dev/null; rm -rf /tmp/rl/*; mkdir -p /tmp/rl; printf '[global]\nlogdir=%s\n[retention]\nmin_free_space=1MB\n[env]\nPATH=/usr/lib/postgresql/17/bin:/usr/bin:/bin\n[postgres]\nstatement_timeout=1s\n[cluster main]\ndatabase=demo_production\n' ${L:-/tmp/rl} > /tmp/r.cfg; cat >> /tmp/r.cfg; : > /tmp/d.log; }
start(){ $A /tmp/r.cfg >>/tmp/d.log 2>&1 & D=$!; sleep ${1:-4}; }
stop(){ kill $D; wait $D; echo "exit=$?"; }
be(){ $M -c "select count(*)||' backends, states '||coalesce(string_agg(state||'/'||coalesce(wait_event,'-'),' '),'-') from pg_stat_activity where application_name like 'sysmon%'"; }
tr(){ grep -c Traceback /tmp/d.log; }
$M -c "create table if not exists live as select g, repeat('x',500) pad from generate_series(1,40000) g" 
BIG='[check big]
interval=1
query=select g, pad from live limit 14000
[check loadavg]
interval=1
file=/proc/loadavg'
say "A SIGSTOP daemon: locks must go"; echo "$BIG" | mk; start 4
for n in 1 2 3 4 5 6 7 8; do kill -STOP $D; sleep .2; $M -c "select count(*) from pg_stat_activity where application_name like 'sysmon%' and state='active'" | grep -q 1 && break; kill -CONT $D; sleep .37; done
be; sleep 8; be; timeout 3 psql -XAtq demo_production -c "alter table live set (fillfactor=90)" && echo "ALTER ok"; kill -CONT $D; sleep 14; be; grep -h '#!' /tmp/rl/main/*/*/*/big* | cut -c1-150; echo "tracebacks $(tr)"; stop

say "B frozen log filesystem"; L=/frozen/l; mkdir -p $L; echo "$BIG" | mk; start 4; touch /tmp/freeze; sleep 12; be; timeout 3 psql -XAtq demo_production -c "alter table live set (fillfactor=91)" && echo "ALTER ok"; for i in $(seq 1 100); do sleep .25; $M -c "select coalesce(max(extract(epoch from clock_timestamp()-query_start)),0)::numeric(6,2) from pg_stat_activity where application_name like 'sysmon%' and state='active'"; done | sort -n | tail -1 | sed 's/^/oldest query s: /'; grep VmRSS /proc/$D/status; tail -2 /tmp/d.log | cut -c1-150; rm /tmp/freeze; sleep 4; a=$(cat $L/os/*/*/*/loadavg*|wc -l); sleep 4; b=$(cat $L/os/*/*/*/loadavg*|wc -l); echo "after thaw +$((b-a))"; stop; unset L

say "C settings do not leak between checks"; mk <<'C'
[check evil]
interval=1
query=select set_config('statement_timeout','0',false), set_config('lock_timeout','0',false), set_config('default_transaction_read_only','off',false), pg_advisory_lock(42)::text
[check see]
interval=1
query=select current_setting('statement_timeout') st, current_setting('lock_timeout') lt, current_setting('transaction_read_only') ro, (select count(*) from pg_locks where locktype='advisory') adv
C
start 6; grep -hv '#' /tmp/rl/main/*/*/*/see* | cut -f3- | sort | uniq -c; stop

say "D startup pile-up: 4 restarts and killed psql with pg_database locked"; mk <<'C'
[check a]
interval=1
query=select 1
C
(echo "begin; lock table pg_database in access exclusive mode; select pg_sleep(75);" | psql -XAtq postgres >/dev/null 2>&1)& sleep 1
st(){ ps -eo args | grep -cE '[p]ostgres: postgres demo_production.*startup'; }
for i in 1 2 3 4; do start 5; echo -n "startup=$(st) psql=$(pgrep -cx psql); "; kill $D; wait $D; done; echo; start 4; for i in 1 2 3 4; do pkill -9 -f 'psql.*sysmon_next'; sleep 5; echo -n "startup=$(st) "; done; echo; kill -9 $D; start 5; echo "after kill -9: startup=$(st)"; tail -2 /tmp/d.log | cut -c1-160; stop; pkill -f pg_sleep; $M -c "select pg_terminate_backend(pid) from pg_stat_activity where query like '%pg_sleep%' and pid<>pg_backend_pid()" >/dev/null; sleep 3

say "E escaping processes"; mk <<'C'
[limits]
command_timeout=1s
[check to]
interval=2
exec=timeout 1111 sleep 1111 | cat
[check ss]
interval=2
exec=setsid sleep 2222 | cat
[check dbl]
interval=2
exec=(setsid sh -c 'sleep 3333 & sleep 3333' >/dev/null 2>&1 &) ; echo started
[check bgok]
interval=2
exec=(sleep 0.3; echo late) & echo early; wait
[check warn]
interval=2
format=table
exec=df -P / /nonexistent
C
start 25; ps -eo args | grep -cE '^(sleep|timeout) [123]'; $A --version >/dev/null; python3 -B /app/sysmon_export.py -l /tmp/rl export os warn | head -3; python3 -B /app/sysmon_export.py -l /tmp/rl export os bgok | head -3; python3 -B /app/sysmon_export.py -l /tmp/rl errors | cut -f2- | sort | uniq -c; kill -9 $D; sleep 2.5; echo "after kill -9: $(ps -eo args | grep -cE '^(sleep|timeout) [123]') watchdogs $(pgrep -fc -- --watchdog)"; echo "tracebacks $(tr)"
say "F SIGCHLD ignored by parent"; mk <<'C'
[check x]
interval=1
exec=echo hi
C
python3 -c "import signal,os;signal.signal(signal.SIGCHLD,signal.SIG_IGN);os.execvp('timeout',['timeout','5','python3','/app/system_monitoring_next.py','--once','/tmp/r.cfg'])" 2>&1 | tail -1; sed -i 's/=1MB/=64MB/' /tmp/r.cfg; python3 -c "import signal,os;signal.signal(signal.SIGCHLD,signal.SIG_IGN);os.execvp('python3',['python3','/app/system_monitoring_next.py','--once','/tmp/r.cfg'])" 2>&1 | tail -1

say "G check that crashes its backend"; mk <<'C'
[check crash]
interval=1
query=select pg_sleep(0.8)
C
start 2; for i in $(seq 1 60); do p=$(pgrep -f 'postgres: postgres demo_production.*COPY' | head -1); [ -n "$p" ] && kill -SEGV $p; sleep .5; done; grep -E 'DISABLED' /tmp/d.log | cut -c1-200; grep -c 'was terminated by signal 11' /tmp/pg5432.log; stop; sleep 3

say "H header repeated in a new file"; mk <<'C'
[check mpstat]
type=persistent
format=mpstat
exec=mpstat 1
[check vmstat]
type=persistent
format=vmstat
exec=vmstat -n 1
C
start 5; rm /tmp/rl/os/*/*/*/*; sleep 4; for c in mpstat vmstat; do head -3 /tmp/rl/os/*/*/*/$c* | cut -c1-90; python3 -B /app/sysmon_export.py -l /tmp/rl export os $c | wc -l; done; kill -HUP $D; sleep 1; kill -0 $D && echo "alive after HUP"; stop

say "I once with unwritable target, typos, duplicates, NULL marker"; mk <<'C'
[check d]
interval=5
query=select 1 as x, 2 as x, '\N' as lit, null as n, 'a'||chr(13)||'b' as cr, 7 as datetime
C
$A --once /tmp/r.cfg 2>/dev/null; echo rc=$?; E="python3 -B /app/sysmon_export.py -l /tmp/rl"; $E export main d | od -c | head -8; $E export main d -f json; LC_ALL=C $E export main d -c nope; echo rc=$?; $E export main d -w nope=1; $E export main d --pivot x:nope; $E export main d -o /dev/null; chmod 500 /tmp/rl/main/*/*/*; rm -f /tmp/rl/main/*/*/*/* 2>/dev/null; chmod 400 /tmp/rl/main/*/*/*/*; $A --once /tmp/r.cfg 2>/dev/null; echo rc=$?

say "J children we did not start must survive (postmaster!)"; mk <<'C'
[check x]
interval=1
exec=setsid sleep 4444 & echo hi
C
rm -rf /tmp/pgw; initdb -D /tmp/pgw -A trust -U postgres >/dev/null; echo "port=5499" >> /tmp/pgw/postgresql.conf
bash -c 'postgres -D /tmp/pgw >/tmp/pgw.log 2>&1 & sleep 600 & exec python3 /app/tests/faults/low.py /tmp/r.cfg' >>/tmp/d.log 2>&1 & D=$!; sleep 10
psql -p 5499 -XAtc "select 'postmaster alive'"; echo "inherited sleep: $(pgrep -fc '^sleep 600')  ours: $(pgrep -fc '^sleep 4444')"
kill -9 $D; sleep 3; psql -p 5499 -XAtc "select 'alive after kill -9 of the daemon'"; echo "ours: $(pgrep -fc '^sleep 4444')"; pg_ctl -D /tmp/pgw -m fast stop >/dev/null; pkill -f '^sleep 600'

say "J2 a check that itself starts PostgreSQL (same session, timed out): not even SIGTERM"; mk <<'C'
[limits]
command_timeout=2s
[check startpg]
interval=600
exec=postgres -D /tmp/pgw >>/tmp/pgw.log 2>&1 & sleep 100
[check execpg]
interval=600
exec=exec postgres -D /tmp/pgw2 >>/tmp/pgw2.log 2>&1
C
rm -rf /tmp/pgw2; initdb -D /tmp/pgw2 -A trust -U postgres >/dev/null; echo "port=5498" >> /tmp/pgw2/postgresql.conf; : > /tmp/pgw.log; : > /tmp/pgw2.log
start 12; for p in 5499 5498; do psql -p $p -XAtc "select 'alive $p, up '||date_trunc('second',now()-pg_postmaster_start_time())"; done; kill $D; wait $D; sleep 2
for p in 5499 5498; do psql -p $p -XAtc "select 'alive after stop $p'"; done; grep -hE 'shutdown|terminat|signal' /tmp/pgw.log /tmp/pgw2.log
start 8; kill -9 $D; sleep 4; for p in 5499 5498; do psql -p $p -XAtc "select 'alive after kill -9 of daemon $p'"; done; grep -hE 'shutdown|terminated by|signal' /tmp/pgw.log /tmp/pgw2.log; pg_ctl -D /tmp/pgw -m fast stop >/dev/null;  pg_ctl -D /tmp/pgw2 -m fast stop >/dev/null

say "K no threads available for a while"; mk <<'C'
[check a]
interval=1
query=select 1
C
start 4; prlimit --pid $D --nproc=1; $M -c "select pg_terminate_backend(pid) from pg_stat_activity where application_name like 'sysmon%'" >/dev/null; sleep 12; prlimit --pid $D --nproc=unlimited 2>/dev/null || echo "(raise as root)"; touch /tmp/raise; echo $D > /tmp/raise; sleep 70; be; grep -h '#!' /tmp/rl/main/*/*/*/a* | cut -c1-140; stop; rm -f /tmp/raise

say "L idle_session_timeout"; psql -XAtqc "alter system set idle_session_timeout='2s'" -c "select pg_reload_conf()" >/dev/null; mk <<'C'
[check a]
interval=4
query=select 1
C
start 18; grep -c '#!' /tmp/rl/main/*/*/*/a*; grep -vc '#' /tmp/rl/main/*/*/*/a*; stop; psql -XAtqc "alter system reset idle_session_timeout" -c "select pg_reload_conf()" >/dev/null
