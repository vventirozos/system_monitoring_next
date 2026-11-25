export PATH=/usr/lib/postgresql/17/bin:$PATH; umask 027
sed 's/host = localhost/host = 127.0.0.1/' /tmp/c.cfg > /tmp/c4.cfg; rm -rf /tmp/logs; mkdir /tmp/logs; :>/tmp/d.log
python3 /app/system_monitoring_next.py /tmp/c4.cfg >>/tmp/d.log 2>&1 & D=$!; sleep 8; touch /tmp/blackhole
for i in 1 2 3 4 5 6 7 8 9; do sleep 10; echo -n "psql5433=$(pgrep -f 'psql.*5433' | wc -l) srv=$(ps -eo args | grep -c '[p]ostgres: postgres postgres 127') main=$(grep -vc '#' /tmp/logs/main/*/*/*/conn_count*); "; done; echo
rm /tmp/blackhole; sleep 60; grep 'cluster second' /tmp/d.log | cut -c1-210; grep -c Traceback /tmp/d.log; kill $D; wait $D; echo exit=$?; ps -ef | grep -c '[p]sql'
