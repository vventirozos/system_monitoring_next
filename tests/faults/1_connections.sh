export PATH=/usr/lib/postgresql/17/bin:$PATH
umask 027
M="psql -XAtq -p 5432 demo_production"
conns(){ psql -XAtqc "select count(*) from pg_stat_activity where application_name like 'sysmon%'" ; }
procs(){ pgrep -c -x psql; }
start(){ python3 /app/system_monitoring_next.py /tmp/f.cfg >>/tmp/d.log 2>&1 & D=$!; sleep ${1:-4}; }
say(){ echo; echo "=== $*"; }
new(){ : >/tmp/d.log; }
# faster intervals, only query checks matter
cat > /tmp/f.cfg <<'C'
[global]
logdir=/tmp/flogs
[env]
PATH=/usr/lib/postgresql/17/bin:/usr/bin:/bin
[retention]
min_free_space=64MB
[postgres]
statement_timeout=1s
lock_timeout=200ms
[cluster main]
database=demo_production
[check act]
interval=1
query=select count(*) from pg_stat_activity
[check sizes]
interval=2
query=select pg_relation_size(oid) from pg_class where relname='t'
[check slow]
interval=2
query=select pg_sleep(20)
[check loadavg]
interval=1
file=/proc/loadavg
format=loadavg
C
rm -rf /tmp/flogs; mkdir /tmp/flogs; new
say "1 baseline + statement timeout"; start 8; echo "conns=$(conns) oom=$(cat /proc/$D/oom_score_adj) nice=$(ps -o ni= -p $D)"; grep -h '#!' /tmp/flogs/main/*/*/*/slow* | head -2
say "2 lock timeout"; (echo "begin; lock table t;select pg_sleep(5);" | $M >/dev/null) & sleep 5; grep -h '#!' /tmp/flogs/main/*/*/*/sizes* | head -1; wait $!
say "3 backend SIGSTOP 25s: must stay at one"; B=$(psql -XAtqc "select pid from pg_stat_activity where application_name like 'sysmon%'"); kill -STOP $B; n0=$(grep -vc '#' /tmp/flogs/os/*/*/*/loadavg*); for i in 1 2 3 4 5; do sleep 5; echo -n "backends=$(conns) psql=$(procs); "; done; echo; n1=$(grep -vc '#' /tmp/flogs/os/*/*/*/loadavg*); echo "os samples continued: +$((n1-n0))"; kill -CONT $B; sleep 12; echo "after CONT backends=$(conns) psql=$(procs)"; tail -4 /tmp/d.log
say "4 kill -9 daemon with stuck backend, restart 3x"; B=$(psql -XAtqc "select pid from pg_stat_activity where application_name like 'sysmon%'"); kill -STOP $B; sleep 3; for i in 1 2 3; do kill -9 $D; sleep .5; start 5; echo "backends=$(conns) psql=$(procs)"; done; tail -2 /tmp/d.log; kill -CONT $B; sleep 2; kill $D; wait $D; echo "exit=$? left: backends=$(conns) psql=$(procs)"
say "5 immediate restart of postgres"; new; start 4; pg_ctl -D /tmp/pg5432 -m immediate stop >/dev/null; sleep 4; pg_ctl -D /tmp/pg5432 -l /tmp/pg5432.log -w start >/dev/null; sleep 16; echo "backends=$(conns)"; cat /tmp/d.log | cut -c1-200
say "6 postmaster stopped while (re)connecting 25s"; P=$(head -1 /tmp/pg5432/postmaster.pid); psql -XAtqc "select pg_terminate_backend(pid) from pg_stat_activity where application_name like 'sysmon%'"; kill -STOP $P; for i in 1 2 3 4 5; do sleep 5; echo -n "psql=$(procs) "; done; kill -CONT $P; sleep 14; echo; echo "backends=$(conns)"; tail -4 /tmp/d.log | cut -c1-220
say "7 catalog lock blocks new connections"; (echo "begin; lock table pg_class in access exclusive mode; select pg_sleep(20);" | $M >/dev/null 2>&1) & L=$!; sleep 1; kill -9 $(pgrep -x psql -P $D); for i in 1 2 3 4; do sleep 5; echo -n "psql=$(pgrep -c -x psql -P $D) backends=$(ps -ef|grep -c '[p]ostgres: postgres demo_production') ; "; done; wait $L; sleep 12; echo "after: backends=$(conns)"; tail -3 /tmp/d.log | cut -c1-220
say "9 idle fds/rss/cpu"; ls /proc/$D/fd | wc -l; grep VmRSS /proc/$D/status; ps -o time=,etimes= -p $D; kill $D; wait $D; echo exit=$?; ps -ef | grep -E "[p]sql|[s]ysmon" | head
