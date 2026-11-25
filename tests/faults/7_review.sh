# Regression tests for the final review (daemon). Run as postgres after setup.sh.
export PATH=/usr/lib/postgresql/17/bin:$PATH; umask 022
A="python3 /app/tests/faults/low.py"; M="psql -XAtq demo_production"
say(){ echo; echo "=== $*"; }
mk(){ rm -rf /tmp/rl; mkdir -p /tmp/rl; printf '[global]\nlogdir=/tmp/rl\n[retention]\nmin_free_space=1MB\n[env]\nPATH=/usr/lib/postgresql/17/bin:/usr/bin:/bin\n[postgres]\nstatement_timeout=1s\n%s\n[cluster main]\ndatabase=demo_production\n' "$P" > /tmp/r.cfg; cat >> /tmp/r.cfg; : > /tmp/d.log; }
start(){ $A /tmp/r.cfg >>/tmp/d.log 2>&1 & D=$!; sleep ${1:-4}; }
stop(){ kill $D; wait $D; echo "exit=$? tracebacks $(grep -c Traceback /tmp/d.log)"; }
Q='[check q]
interval=1
query=select g, pad from live limit 14000'
$M -c "create table if not exists live as select g, repeat('x',500) pad from generate_series(1,40000) g"

say "A standby with a running restore_command, started by a check; daemon killed"
rm -rf /tmp/sb; pg_basebackup -D /tmp/sb -p 5432 -R -c fast; printf "port=5497\nrestore_command='sleep 30; false'\n" >> /tmp/sb/postgresql.conf
mk <<'C'
[check sb]
interval=600
exec=pg_ctl -D /tmp/sb -l /tmp/sb.log -W start
[check sb2]
interval=600
exec=sleep 3600
C
: > /tmp/sb.log; start 6; pgrep -af 'sleep 30' | head -2; kill -9 $D; sleep 4; pgrep -fc 'sleep 30' ; grep -hE 'signal 9|shut down' /tmp/sb.log; pg_ctl -D /tmp/sb status | head -1; echo "our own sleep 3600 left: $(pgrep -fc '^sleep 3600')"
start 5; stop; pg_ctl -D /tmp/sb status | head -1; pg_ctl -D /tmp/sb -m immediate stop >/dev/null

say "B renamed postgres binary in a session of ours and in its own, timeout and kill -9"
rm -rf /tmp/rn; cp -r /usr/lib/postgresql/17 /tmp/rn; mv /tmp/rn/bin/postgres /tmp/rn/bin/pgsrv17; mkdir -p /tmp/rnx; for i in 1 2; do rm -rf /tmp/rnd$i; initdb -D /tmp/rnd$i -A trust -U postgres >/dev/null; echo "port=549$i" >> /tmp/rnd$i/postgresql.conf; done
mk <<'C'
[limits]
command_timeout=2s
[check r1]
interval=600
exec=/tmp/rn/bin/pgsrv17 -D /tmp/rnd1 -c dynamic_library_path=/usr/lib/postgresql/17/lib >/tmp/rn1.log 2>&1 & sleep 50
[check r2]
interval=600
exec=setsid /tmp/rn/bin/pgsrv17 -D /tmp/rnd2 >/tmp/rn2.log 2>&1 & echo x
C
start 12; pgrep -xc pgsrv17 | sed 's/^/pgsrv17 processes /'; for i in 1 2; do psql -p 549$i -XAtc "select 'alive $i'" ; done; kill -9 $D; sleep 3; for i in 1 2; do psql -p 549$i -XAtc "select 'alive after kill -9 $i'"; done; grep -hE 'shut|signal' /tmp/rn[12].log; for i in 1 2; do kill -INT $(head -1 /tmp/rnd$i/postmaster.pid); done; sleep 2

say "C psql stopped while the server sends"; echo "$Q" | mk; start 3
for i in $(seq 1 60); do pkill -STOP -x psql -f 2>/dev/null; pkill -STOP -f '^psql.*sysmon_next'; sleep .1; $M -c "select 1 from pg_stat_activity where application_name like 'sysmon%' and wait_event='ClientWrite'" | grep -q 1 && break; pkill -CONT -f '^psql.*sysmon_next'; sleep .13; done
$M -c "select state, wait_event, backend_xmin from pg_stat_activity where application_name like 'sysmon%'"; sleep 14; echo "14s later: $($M -c "select count(*) from pg_stat_activity where application_name like 'sysmon%' and now()-query_start > '10s' and state='active'") old active"; grep -h 'stopped or hung' /tmp/d.log | cut -c1-120; sleep 12; grep -c connected /tmp/d.log; stop

say "D renamed psql: startup pile-up"; cp /usr/lib/postgresql/17/bin/psql /tmp/pgcli17; P="psql=/tmp/pgcli17"; mk <<'C'
[check a]
interval=1
query=select 1
C
(echo "begin; lock table pg_database in access exclusive mode; select pg_sleep(40);" | psql -XAtq postgres >/dev/null 2>&1)& sleep 1
for i in 1 2 3 4; do start 5; echo -n "startup=$(ps -eo args | grep -cE '[p]ostgres: postgres demo_production.*startup') "; kill -9 $D; wait $D 2>/dev/null; done; echo
psql -XAtqc "select pg_terminate_backend(pid) from pg_stat_activity where query like '%pg_sleep%' and pid<>pg_backend_pid()" postgres >/dev/null; sleep 4
say "E psql wrapper is refused"; printf '#!/bin/sh\n/usr/lib/postgresql/17/bin/psql "$@"\n' > /tmp/wrap.sh; chmod 755 /tmp/wrap.sh; P="psql=/tmp/wrap.sh"; echo "$Q" | mk; start 6; grep -h 'must be psql' /tmp/d.log | head -1 | cut -c1-140; stop; P=

say "F register fails once: cluster recovers"; echo "$Q" | mk; cat > /tmp/inj.py <<'C'
import sys; sys.path.insert(0, "/app"); sys.dont_write_bytecode = True
import system_monitoring_next as sm
sm.MIN_FREE_FLOOR, sm.MIN_SIZE_FLOOR = 0, 1
real, n = sm.selectors.DefaultSelector.register, [0]
def reg(self, *a, **k):
    n[0] += 1
    if n[0] == 2: raise OSError(12, "injected ENOMEM")
    return real(self, *a, **k)
sm.selectors.DefaultSelector.register = reg
sm.main()
C
python3 /tmp/inj.py /tmp/r.cfg >>/tmp/d.log 2>&1 & D=$!; sleep 16; grep -hE 'injected|connected' /tmp/d.log | cut -c1-140; stop

say "G escaping processes are counted, not killed, and stop at 8"; mk <<'C'
[check e]
interval=1
exec=setsid sleep 5555 >/dev/null 2>&1 & echo x
[check own]
interval=1
exec=(sleep 6666 &) ; echo y
[check lavg]
interval=1
file=/proc/loadavg
C
start 35; echo "escaped $(pgrep -fc '^sleep 5555') in-session left $(pgrep -fc '^sleep 6666')"; grep -h 'unkillable\|left behind' /tmp/d.log | cut -c1-150; echo "loadavg lines $(cat /tmp/rl/os/*/*/*/lavg*|wc -l)"; pkill -f '^sleep 5555'; sleep 5; echo "commands again: $(tail -1 /tmp/rl/os/*/*/*/own* | cut -c1-19) now $(date '+%F %T')"; stop; pkill -f '^sleep [56]'

say "H a check that changed its directory is not signalled but reported; unkillable costs no cpu"; mk <<'C'
[limits]
command_timeout=1s
[check cd]
interval=600
exec=cd /tmp && exec sleep 40
[check ok]
interval=600
exec=cd /proc/1 ; exec sleep 41
C
start 4; a=$(awk '{print $14+$15}' /proc/$D/stat); sleep 10; echo "ticks in 10s: $(( $(awk '{print $14+$15}' /proc/$D/stat) - a ))  cd-sleep $(pgrep -fc '^sleep 40') proc-sleep $(pgrep -fc '^sleep 41')"; grep -h 'does not die' /tmp/d.log | cut -c1-100; stop; pkill -f '^sleep 40'

say "I pg_stat_statements is not flooded"; $M -c "select pg_stat_statements_reset()" >/dev/null; printf '%s\n[check two]\ninterval=1\nquery=select 1 as a, null as b\n' "$Q" | mk; start 20; $M -c "select count(*)||' entries, '||sum(calls)||' calls' from pg_stat_statements where query ~* 'copy|discard|sqlstate|set '"; stop; grep -hv '#' /tmp/rl/main/*/*/*/two* | tail -1

say "J second daemon on the same cluster logdir"; mkdir -p /tmp/rl3 /tmp/rl4 /tmp/shared; for n in 3 4; do printf '[global]\nlogdir=/tmp/rl%s\n[cluster main]\nlogdir=/tmp/shared\n[check a]\ninterval=1\nquery=select 1\n' $n > /tmp/r$n.cfg; done; $A /tmp/r3.cfg >/dev/null 2>&1 & D=$!; sleep 2; timeout 5 $A /tmp/r4.cfg 2>&1 | tail -1; kill $D; wait $D
