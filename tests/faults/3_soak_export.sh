export PATH=/usr/lib/postgresql/17/bin:$PATH; umask 027
say(){ echo; echo "=== $*"; }
start(){ python3 /app/tests/faults/low.py $1 >>/tmp/d.log 2>&1 & D=$!; sleep $2; }
stop(){ kill $D; wait $D; echo "exit=$?"; }
X="python3 -W error -B /app/sysmon_export.py -l /tmp/logs"
say "20 yes volume / big SQL"
rm -rf /tmp/glogs /tmp/d.log; mkdir /tmp/glogs; cat > /tmp/g.cfg <<'C'
[global]
logdir=/tmp/glogs
[retention]
min_free_space=64MB
[limits]
command_timeout=2s
[cluster main]
database=demo_production
[check yes]
interval=5
exec=yes
[check bigsql]
interval=3
query=select g, repeat('x',300) as pad from generate_series(1,200000) g
[check manyrows]
interval=3
query=select g from generate_series(1,300000) g
[check rowserr]
interval=3
query=select 1/(50-g) from generate_series(1,100) g
[check weird]
interval=3
query=select E'a\tb\nc' as "col	tab", null as n, '' as e, '\N' as lit, E'\\N' as l2, 'x"y,z' as q
[check psqlvars]
interval=3
query=select 'a'::text as t, '{1,2,3}'::int[] as a, (array[1,2,3])[1:2] as sl, '@nope' as at
C
start /tmp/g.cfg 20; grep VmHWM /proc/$D/status; ps -o time=,etimes= -p $D; du -sk /tmp/glogs; kill $D; wait $D
G="python3 -B /app/sysmon_export.py -l /tmp/glogs"; $G errors | cut -f2- | sort | uniq -c; $G export main weird -f json --time plain| head -1; $G export main weird --null NULL | head -4; $G export main psqlvars|head -2; grep -c Traceback /tmp/d.log
say "21 soak with real config 100s, cpu/fd/rss"; rm -rf /tmp/logs /tmp/second_logs; mkdir /tmp/logs; : > /tmp/d.log
pgbench -iq -s 2 demo_production 2>/dev/null; pgbench -c 4 -T 95 demo_production >/dev/null 2>&1 &
start /tmp/c.cfg 5; ls /proc/$D/fd|wc -l; grep VmRSS /proc/$D/status; sleep 45; ls /proc/$D/fd|wc -l
psql -XAtc "select count(*) from pg_stat_activity where application_name like 'sysmon%'"
sleep 50; ls /proc/$D/fd|wc -l; grep VmRSS /proc/$D/status; ps -o time=,etimes= -p $D; cat /proc/$D/stat | awk '{print "cpu ticks self",$14+$15,"children",$16+$17}'; du -sh /tmp/logs
say "22 TCP blackhole to second (root rule applied outside)"; touch /tmp/blackhole; sleep 45; echo "psql to 5433: $(pgrep -af 'psql.*5433' | wc -l)"; grep second /tmp/d.log | grep -v SQLSTATE | tail -4 | cut -c1-200; rm /tmp/blackhole; sleep 25; grep second /tmp/d.log | grep connected; stop
say "23 export"
$X list
for c in iostat vmstat mpstat ps df free loadavg mem cpu pg_processes; do echo "--$c"; $X export os $c | cut -c1-170 | sed -n '1,3p'; done
$X export main conn_count -f table --last 10m | head -4
$X export os pg_processes --where port=5432 --pivot state:count --time plain | tail -3
$X export main full_activity -n all -c pid,x_age,state --time epoch | head -3
$X export _daemon runs -c target,check,status,duration_ms -f table | tail -2
$X export main database_size --pivot datname:size | head -2
$X export /tmp/second_logs conn_count -f table | head -3
$X export os nope; $X export os vmstat --last 10s -o /tmp/o.csv && wc -l /tmp/o.csv
head -4 /tmp/logs/main/*/*/*/conn_count*
