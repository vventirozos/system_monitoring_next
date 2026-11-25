export PATH=/usr/lib/postgresql/17/bin:$PATH; umask 027; D=0
say(){ echo; echo "=== $*"; }
start(){ python3 /app/tests/faults/low.py $1 >>/tmp/d.log 2>&1 & D=$!; sleep $2; }
stop(){ kill $D; wait $D; echo "exit=$?"; }
say "8 max_connections exhausted"; rm -rf /tmp/flogs; mkdir /tmp/flogs; :>/tmp/d.log; start /tmp/f.cfg 5
for i in $(seq 1 40); do (echo 'select pg_sleep(10);' | psql -XAtq >/dev/null 2>&1)& done; sleep 2
psql -XAtqc 'select 1' 2>&1 | cut -c1-120; a=$(grep -vc '#' /tmp/flogs/main/*/*/*/act*); sleep 6; b=$(grep -vc '#' /tmp/flogs/main/*/*/*/act*); echo "samples while full: +$((b-a))"; sleep 5; stop

say "10 hostile commands"
cat > /tmp/g.cfg <<'C'
[global]
logdir=/tmp/glogs
[retention]
min_free_space=64MB
[limits]
max_output=1MB
command_timeout=2s
max_memory=256MB
[check ignoreterm]
interval=3
exec=trap '' TERM; sleep 1234 & sleep 1234; sleep 1234
[check yes]
interval=3
exec=yes
[check grandchild]
interval=3
exec=sleep 4321 & echo done
[check bg_silent]
interval=3
exec=sleep 5432 >/dev/null 2>&1 & echo done
[check missing]
interval=3
exec=/no/such/thing
[check memhog]
interval=3
exec=python3 -c "x='a'*(10**9)"
[check flood]
type=persistent
exec=while :; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done
[check dies]
type=persistent
exec=echo hello; exit 3
[check binary]
interval=3
exec=head -c 3000 /dev/urandom
[check nonl]
interval=3
exec=printf 'a\tb\nno newline'
C
rm -rf /tmp/glogs; mkdir /tmp/glogs; :>/tmp/d.log; start /tmp/g.cfg 45
ps -eo pid,ppid,pgid,stat,args | grep -E '[s]leep (1234|4321|5432)|[y]es|[w]hile' 
grep VmHWM /proc/$D/status; ps -o time=,etimes= -p $D; du -k /tmp/glogs/os/*/*/*/* ; stop; sleep 1; ps -eo args | grep -cE '[s]leep (1234|4321|5432)'
python3 /app/sysmon_export.py -l /tmp/glogs errors | cut -f2- | sort | uniq -c
python3 /app/sysmon_export.py -l /tmp/glogs export os nonl | head -3
grep -v '^\d' /tmp/d.log | grep -A5 -i traceback

say "11 disk full (3MB tmpfs)"; sed -e 's#/tmp/glogs#/small#; s#=64MB#=0MB#' /tmp/g.cfg > /tmp/h.cfg; :>/tmp/d.log; start /tmp/h.cfg 20; df -k /small | tail -1; cut -c1-150 /tmp/d.log | grep -i 'write'; head -c 1 /dev/null; ls -la /small/os/*/*/* | head -4; kill -0 $D && echo alive
for f in /small/os/*/*/*/yes*; do : > $f; done; sleep 12; grep -c . /small/os/*/*/*/nonl*; stop
say "11b min_free_space"; sed -e 's#/small#/small2#; s#=0MB#=4MB#' /tmp/h.cfg > /tmp/i.cfg; :>/tmp/d.log; start /tmp/i.cfg 6; grep -h 'NOT writing' /tmp/d.log; find /small2 -type f ; stop

say "12 cleanup only touches our files"
L=/tmp/clogs; rm -rf $L /tmp/victim; mkdir -p $L/os/2026/11/2{0,1,4} $L/os/2025/01/01 /tmp/victim/2026/11/20; cd $L/os/2026/11/20
echo x > mem-2026-11-20-01.tsv; echo x > mem-2026-11-20-01.tsv.gz; echo keepme > notes.txt; echo keepme > mem-2026-11-20-01.log; echo keepme > mem-2026-11-19-01.tsv; ln -s /etc/passwd ps-2026-11-20-02.tsv; mkdir df-2026-11-20-03.tsv
echo v > /tmp/victim/2026/11/20/mem-2026-11-20-01.tsv; ln -s /tmp/victim/2026 $L/os/2027
echo t > cpu-2026-11-20-01.tsv.gz.tmp; find . -type f -exec touch -d '5 days ago' {} +; touch -d '5 days ago' /tmp/victim/2026/11/20/*
cd ../24; seq 1 1000 > mem-2026-11-24-01.tsv; touch -d '30 hours ago' mem*; echo long > keepit-2026-11-24-01.tsv; touch -d '90 days ago' keepit*
cat > /tmp/cl.cfg <<'C'
[global]
logdir=/tmp/clogs
[retention]
min_free_space=64MB
[check loadavg]
interval=1
file=/proc/loadavg
[check keepit]
interval=50
keep=365d
file=/proc/loadavg
C
:>/tmp/d.log; start /tmp/cl.cfg 8; find $L /tmp/victim | sort; zcat $L/os/2026/11/24/mem*gz | wc -l; cat /tmp/d.log; start /tmp/cl.cfg 1; tail -1 /tmp/d.log; kill $(cat $L/pidfile); sleep 2
say "12b max_total_size"; for i in 1 2 3; do head -c 400000 /dev/urandom > $L/os/2026/11/24/big-2026-11-24-0$i.tsv; done; sed -i 's/\[retention\]/[retention]\nmax_size_per_target=1MB\nmax_file_size=1MB/' /tmp/cl.cfg; :>/tmp/d.log; start /tmp/cl.cfg 8; ls $L/os/2026/11/24; grep -v INFO /tmp/d.log; stop

say "13 pg_processes vs perl"
(echo 'select pg_sleep(4);' | psql -q >/dev/null)& (echo "begin; select pg_sleep(3);select 1/0;" | psql -q >/dev/null 2>&1)& (cat <<<'begin;select 1/0;
\! sleep 4' | psql -q >/dev/null 2>&1)& (echo 'select pg_sleep(4);' | psql -q -h localhost -p 5433 >/dev/null)& sleep 1
python3 /app/system_monitoring_next.py --pg-processes
perl -e 'for (`ps -A -C postgres o cmd=`) {next if!s/^postgres:.*[)\]]\s*//;s/\s*\z//;$c{$_}++;$s++} print "$s:"; print " $c{$_}($_)" for sort keys %c; print"\n"'
wait $(jobs -p) 2>/dev/null
