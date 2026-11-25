umask 022
set -e
export PATH=/usr/lib/postgresql/17/bin:$PATH
for p in 5432 5433; do
 initdb -D /tmp/pg$p -A trust -U postgres >/dev/null
 echo "port=$p
listen_addresses='localhost'
max_connections=30
shared_preload_libraries='pg_stat_statements'" >> /tmp/pg$p/postgresql.conf
 pg_ctl -D /tmp/pg$p -l /tmp/pg$p.log -w start >/dev/null
done
psql -qc "create database demo_production"
psql -Xq demo_production -f /app/dba_schema.v3.sql >/dev/null 2>&1
psql -q demo_production <<'Q'
create table t(i int primary key); create table ext(i int);
Q
sed -e 's#/data/system_monitoring_next_logs#/tmp/logs#' -e 's#^interval = 60#interval = 10#' -e 's#min_free_space = 2GB#min_free_space = 100MB#' /app/config.sample > /tmp/c.cfg
sed -i 's#^exec     = cd /proc/pressure.*#exec = echo a b; echo 1 2#' /tmp/c.cfg   # kernel of the test VM has no PSI
cat >> /tmp/c.cfg <<'C'
[cluster second]
port = 5433
host = localhost
logdir = /tmp/second_logs
C
mkdir -p /tmp/logs /tmp/second_logs; python3 /app/system_monitoring_next.py -t /tmp/c.cfg
python3 /app/system_monitoring_next.py --once /tmp/c.cfg
