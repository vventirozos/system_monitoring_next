-- ============================================================================
-- dba monitoring schema
-- Target: PostgreSQL 17+
-- Idempotent: safe to re-run. Re-running resets dba.alert_state_config.
--
-- Requires: shared_preload_libraries = 'pg_stat_statements'
-- ============================================================================

\set ON_ERROR_STOP on

CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS btree_gist;      -- for the range EXCLUDE constraint

CREATE SCHEMA IF NOT EXISTS dba;

-- Views cannot be CREATE OR REPLACE'd across column changes, so drop first.
DROP VIEW IF EXISTS dba.alert_silenced         CASCADE;
DROP VIEW IF EXISTS dba.alert_state_missing    CASCADE;
DROP VIEW IF EXISTS dba.state                  CASCADE;
DROP VIEW IF EXISTS dba.alert_state            CASCADE;
DROP VIEW IF EXISTS dba.lock_dependencies      CASCADE;
DROP VIEW IF EXISTS dba.lock_hierarchy         CASCADE;
DROP VIEW IF EXISTS dba.lock                   CASCADE;
DROP VIEW IF EXISTS dba.activity               CASCADE;
DROP VIEW IF EXISTS dba.stat_activity          CASCADE;
DROP VIEW IF EXISTS dba.stat_statements        CASCADE;
DROP VIEW IF EXISTS dba.xid_age                CASCADE;
DROP VIEW IF EXISTS dba.int_overflow           CASCADE;
DROP VIEW IF EXISTS dba.sequence_exhaustion    CASCADE;
DROP FUNCTION IF EXISTS dba.public_replication_lag() CASCADE;
DROP VIEW IF EXISTS dba.replication_lag        CASCADE;


-- ============================================================================
-- helper
-- ============================================================================

CREATE OR REPLACE FUNCTION dba.norm(text) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT
    RETURN btrim(regexp_replace($1, '\s+', ' ', 'g'));

COMMENT ON FUNCTION dba.norm(text) IS
    'Collapse runs of whitespace to single spaces and trim.';


-- ============================================================================
-- activity
-- ============================================================================

-- LATERAL, not (f(x)).* -- the latter re-evaluates the function once per
-- output column (43x on pg_stat_statements, confirmed via EXPLAIN VERBOSE:
-- 168 ms vs 4.2 ms on 86 rows). The jsonb round-trip keeps the column set
-- correct across major versions that add, drop or reorder columns.
CREATE VIEW dba.stat_activity AS
SELECT r.*
FROM pg_stat_activity s
CROSS JOIN LATERAL jsonb_populate_record(
        NULL::pg_stat_activity,
        to_jsonb(s) || jsonb_build_object('query', dba.norm(s.query))
     ) AS r;

COMMENT ON VIEW dba.stat_activity IS
    'pg_stat_activity with whitespace-normalized query. Column set tracks the server version automatically.';


CREATE VIEW dba.activity AS
SELECT now() - xact_start          AS x_age,
       now() - query_start         AS q_age,
       pid,
       datname,
       usename,
       application_name,
       state,
       wait_event_type,
       wait_event,
       backend_type,
       left(dba.norm(query), 80)   AS query
FROM pg_stat_activity
WHERE state IS DISTINCT FROM 'idle'
  AND pid <> pg_backend_pid()
ORDER BY xact_start NULLS LAST;

COMMENT ON VIEW dba.activity IS
    'Non-idle backends, oldest transaction first. Excludes the calling backend.';


-- ============================================================================
-- locks
-- ============================================================================

-- pg_blocking_pids() replaces the 12-way self-join on pg_locks: it also
-- understands parallel workers, prepared xacts and lock-queue ordering, and
-- it cannot report two waiters as blocking each other.
CREATE VIEW dba.lock AS
SELECT blocker.pid                          AS blocking_pid,
       blocker.usename                      AS blocking_user,
       left(dba.norm(blocker.query), 60)    AS blocking_statement,
       blocker.state                        AS blocking_state,
       blocked.pid                          AS blocked_pid,
       blocked.usename                      AS blocked_user,
       left(dba.norm(blocked.query), 60)    AS blocked_statement,
       blocked.wait_event_type              AS blocked_wait_event_type,
       blocked.wait_event                   AS blocked_wait_event,
       now() - blocked.state_change         AS blocked_duration
FROM pg_stat_activity blocked
CROSS JOIN LATERAL unnest(pg_blocking_pids(blocked.pid)) AS b(blocking_pid)
JOIN pg_stat_activity blocker ON blocker.pid = b.blocking_pid
WHERE blocked.wait_event_type = 'Lock';

COMMENT ON VIEW dba.lock IS
    'Blocked/blocking backend pairs via pg_blocking_pids().';


-- pg_blocking_pids() also returns the waiters queued ahead, so following every
-- edge gives 2^n paths for n waiters on one lock (25 waiters = 33 million rows).
-- Each waiter therefore follows ONE blocker: preferably one that is not waiting
-- itself, else the one waiting longest. Result: at most one row per waiter.
-- A waiter blocked by several sessions shows one of them, and one root.
-- All blockers of a waiter are in dba.lock. path[] gives cycle detection; members
-- of a deadlock have no root and are not shown, as before.
CREATE VIEW dba.lock_hierarchy AS
WITH RECURSIVE waiter AS MATERIALIZED (
    SELECT a.pid, pg_blocking_pids(a.pid) AS blockers
    FROM pg_stat_activity a
    WHERE a.wait_event_type = 'Lock'
), since AS MATERIALIZED (
    SELECT l.pid, min(l.waitstart) AS waitstart
    FROM pg_locks l
    WHERE NOT l.granted
    GROUP BY l.pid
), edge AS MATERIALIZED (
    SELECT DISTINCT ON (w.pid) b.blocking_pid, w.pid AS blocked_pid
    FROM waiter w
    CROSS JOIN LATERAL unnest(w.blockers) AS b(blocking_pid)
    LEFT JOIN waiter q ON q.pid = b.blocking_pid
    LEFT JOIN since  s ON s.pid = b.blocking_pid
    ORDER BY w.pid, (q.pid IS NOT NULL), s.waitstart NULLS LAST, b.blocking_pid
), chain AS (
    SELECT e.blocking_pid                        AS root_pid,
           1                                     AS depth,
           e.blocked_pid,
           ARRAY[e.blocking_pid, e.blocked_pid]  AS path
    FROM edge e
    WHERE NOT EXISTS (SELECT 1 FROM edge p WHERE p.blocked_pid = e.blocking_pid)
    UNION ALL
    SELECT c.root_pid,
           c.depth + 1,
           e.blocked_pid,
           c.path || e.blocked_pid
    FROM chain c
    JOIN edge e ON e.blocking_pid = c.blocked_pid
    WHERE NOT e.blocked_pid = ANY (c.path)      -- cycle guard
      AND c.depth < 100
)
SELECT root_pid,
       depth,
       path[depth]  AS blocking_pid,
       blocked_pid  AS pid,
       path
FROM chain;

COMMENT ON VIEW dba.lock_hierarchy IS
    'Lock-wait chains rooted at backends that block but are not themselves blocked. One row per waiter.';


-- Not joined to dba.lock: that has one row per waiter AND blocker (n^2/2).
-- LEFT JOIN: a prepared transaction blocks as pid 0.
CREATE VIEW dba.lock_dependencies AS
SELECT h.blocking_pid,
       left(dba.norm(blocker.query), 60)    AS blocking_statement,
       h.pid                                AS blocked_pid,
       left(dba.norm(blocked.query), 60)    AS blocked_statement,
       now() - blocked.state_change         AS blocked_duration,
       h.root_pid,
       h.depth,
       h.path                               AS sequence_of_locks
FROM dba.lock_hierarchy h
JOIN pg_stat_activity blocked      ON blocked.pid = h.pid
LEFT JOIN pg_stat_activity blocker ON blocker.pid = h.blocking_pid
ORDER BY blocked_duration DESC;


-- ============================================================================
-- statements
-- ============================================================================

CREATE VIEW dba.stat_statements AS
SELECT r.*
FROM pg_stat_statements s
CROSS JOIN LATERAL jsonb_populate_record(
        NULL::pg_stat_statements,
        to_jsonb(s) || jsonb_build_object('query', dba.norm(s.query))
     ) AS r;

COMMENT ON VIEW dba.stat_statements IS
    'pg_stat_statements with whitespace-normalized query. Recreate after ALTER EXTENSION pg_stat_statements UPDATE.';


-- ============================================================================
-- overflow risk
-- ============================================================================

-- Reads planner statistics, so it is cheap but only as fresh as the last
-- ANALYZE. Uses histogram_bounds AND most_common_vals: a column whose maximum
-- is an MCV is absent from the histogram entirely.
CREATE VIEW dba.int_overflow AS
WITH cols AS (
    SELECT n.nspname, c.relname, a.attname,
           format_type(a.atttypid, NULL) AS type,
           CASE a.atttypid
                WHEN 'smallint'::regtype   THEN 32767
                WHEN 'smallint[]'::regtype THEN 32767
                ELSE 2147483647
           END::bigint AS type_max,
           format_type(a.atttypid, NULL) LIKE '%[]' AS is_array
    FROM pg_attribute a
    JOIN pg_class     c ON c.oid = a.attrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind IN ('r','p','m')
      AND a.attnum > 0
      AND NOT a.attisdropped
      AND a.atttypid IN ('integer'::regtype,   'smallint'::regtype,
                         'integer[]'::regtype, 'smallint[]'::regtype)
      AND n.nspname NOT IN ('pg_catalog','information_schema')
), src AS (
    SELECT c.*, t.arr
    FROM cols c
    JOIN pg_stats s
      ON s.schemaname = c.nspname AND s.tablename = c.relname AND s.attname = c.attname
    CROSS JOIN LATERAL (VALUES (s.histogram_bounds::text),
                               (s.most_common_vals::text)) AS t(arr)
    WHERE t.arr IS NOT NULL
), vals AS (
    SELECT nspname, relname, attname, type, type_max, v
    FROM src, LATERAL unnest(src.arr::bigint[]) v
    WHERE NOT is_array
    UNION ALL
    SELECT nspname, relname, attname, type, type_max, v
    FROM src,
         LATERAL unnest(src.arr::text[]) e,
         LATERAL unnest(e::bigint[])     v
    WHERE is_array
)
SELECT now()::timestamp(0) AS now,
       nspname AS schemaname,
       relname AS tablename,
       attname,
       type,
       min(v) AS min,
       max(v) AS max,
       round(100.0 * max(v) / type_max, 2) AS pct_of_type_max
FROM vals
GROUP BY nspname, relname, attname, type, type_max
ORDER BY 8 DESC;

COMMENT ON VIEW dba.int_overflow IS
    'int/smallint columns ranked by how close their observed max is to the type limit. Based on planner stats - only as fresh as the last ANALYZE.';


CREATE VIEW dba.sequence_exhaustion AS
SELECT schemaname, sequencename, data_type, last_value, max_value,
       round(100.0 * last_value / max_value, 2) AS pct_used
FROM pg_sequences
WHERE last_value IS NOT NULL
ORDER BY pct_used DESC;

COMMENT ON VIEW dba.sequence_exhaustion IS
    'Sequences ranked by proportion of their range consumed.';


-- ============================================================================
-- replication
-- ============================================================================

CREATE VIEW dba.replication_lag AS
SELECT application_name                     AS replica,
       coalesce(client_addr::text, 'local') AS client,
       state,
       sync_state,
       extract(epoch FROM coalesce(replay_lag, '0'::interval))::bigint AS seconds_behind,
       pg_wal_lsn_diff(sent_lsn, replay_lsn)::bigint                   AS replay_bytes_behind
FROM pg_stat_replication;

-- SECURITY DEFINER must pin search_path. If your monitoring role can be
-- granted pg_monitor, drop this function and read the view directly.
CREATE FUNCTION dba.public_replication_lag()
    RETURNS SETOF dba.replication_lag
    LANGUAGE sql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
    STABLE
    AS $$ SELECT * FROM dba.replication_lag $$;

REVOKE ALL ON FUNCTION dba.public_replication_lag() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION dba.public_replication_lag() TO PUBLIC;


-- ============================================================================
-- alerting
-- ============================================================================

-- Dropped and recreated rather than CREATE TABLE IF NOT EXISTS: a table left
-- over from an earlier version of this script has neither the newer columns
-- nor the constraints, and IF NOT EXISTS would silently skip all of it. The
-- rows are rewritten below in full, so nothing is lost that this script does
-- not restore. To carry across thresholds you tuned in place, dump them first:
--   \copy (SELECT * FROM dba.alert_state_config) TO 'asc.bak.csv' CSV HEADER
-- CASCADE also removes the sequence, whether it is a legacy OWNED BY sequence
-- or the one behind the identity column.
DROP TABLE IF EXISTS dba.alert_state_config CASCADE;

CREATE TABLE dba.alert_state_config (
    id             integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    check_id       integer NOT NULL,
    description    text    NOT NULL,
    threshold_min  bigint  NOT NULL,
    threshold_high bigint  NOT NULL,
    alert_type     text    NOT NULL CHECK (alert_type IN ('OK','WARNING','ALERT')),
    will_page      boolean NOT NULL DEFAULT false,
    -- Some checks only make sense on one side of a replication pair.
    role_scope     text    NOT NULL DEFAULT 'any'
                   CHECK (role_scope IN ('any','primary','standby')),
    -- Set-valued checks emit one row per replica / per slot, so zero rows is a
    -- legitimate result and must not be reported as a missing producer.
    is_set         boolean NOT NULL DEFAULT false,
    CONSTRAINT threshold_order CHECK (threshold_min < threshold_high),
    CONSTRAINT no_overlapping_bands EXCLUDE USING gist (
        check_id WITH =,
        int8range(threshold_min, threshold_high) WITH &&
    )
);

INSERT INTO dba.alert_state_config
  (id, check_id, description, threshold_min, threshold_high, alert_type, will_page)
VALUES
  (1,  1,  'Connection count',                    0,             200,           'OK',      false),
  (2,  1,  'Connection count',                    200,           250,           'WARNING', true),
  (3,  1,  'Connection count',                    250,           999999999,     'ALERT',   true),
  (4,  2,  'LWLock count',                        0,             50,            'OK',      false),
  (5,  2,  'LWLock count',                        50,            100,           'WARNING', true),
  (6,  2,  'LWLock count',                        100,           999999999,     'ALERT',   true),
  (7,  3,  'Vacuums blocked',                     0,             5,             'OK',      false),
  (8,  3,  'Vacuums blocked',                     5,             10,            'WARNING', true),
  (9,  3,  'Vacuums blocked',                     10,            999999999,     'ALERT',   true),
  (10, 4,  'Processes blocked',                   0,             21,            'OK',      false),
  (11, 4,  'Processes blocked',                   21,            31,            'WARNING', true),
  (12, 4,  'Processes blocked',                   31,            999999999,     'ALERT',   true),
  (13, 5,  'Total locks',                         0,             120000,        'OK',      false),
  (14, 5,  'Total locks',                         120000,        200000,        'WARNING', false),
  (15, 5,  'Total locks',                         200000,        999999999,     'ALERT',   false),
  (16, 6,  'Oldest idle transaction (minutes)',   0,             180,            'OK',      false),
  (17, 6,  'Oldest idle transaction (minutes)',   180,            240,            'WARNING', false),
  (18, 6,  'Oldest idle transaction (minutes)',   240,            999999999,     'ALERT',   false),
  (19, 7,  'Oldest active transaction (minutes)', 0,             60,            'OK',      false),
  (20, 7,  'Oldest active transaction (minutes)', 60,            90,            'WARNING', false),
  (21, 7,  'Oldest active transaction (minutes)', 90,            999999999,     'ALERT',   false),
  -- Check 8 is inverted on purpose: small value = failure was recent = bad.
  -- NOTE: id 24 (ALERT) does not page while id 23 (WARNING) does. Looks
  --       backwards - flip will_page if you agree.
  (22, 8,  'Last archiving failure (minutes)',    10,            999999999,     'OK',      false),
  (23, 8,  'Last archiving failure (minutes)',    5,             10,            'WARNING', true),
  (24, 8,  'Last archiving failure (minutes)',    0,             5,             'ALERT',   false),
  (25, 9,  'Replication delay (seconds)',         0,             7200,          'OK',      false),
  (26, 9,  'Replication delay (seconds)',         7200,          36000,         'WARNING', false),
  (27, 9,  'Replication delay (seconds)',         36000,         59999999940,   'ALERT',   false),
  -- 100 GiB / 130 GiB. Only the top band pages: 'extended' wal_status is
  -- normal here, so size is the paging signal, not slot status (see check 16).
  (28, 10, 'Replication slot retained bytes',     0,             107374182400,  'OK',      false),
  (29, 10, 'Replication slot retained bytes',     107374182400,  139586437120,  'WARNING', false),
  (30, 10, 'Replication slot retained bytes',     139586437120,  9999999999999, 'ALERT',   true),
  -- 13/14: wraparound. The cluster refuses writes near 2.1B and recovery is a
  -- single-user-mode vacuum. MultiXact is a separate counter, same failure.
  (38, 13, 'Oldest datfrozenxid age',             0,             900000000,     'OK',      false),
  (39, 13, 'Oldest datfrozenxid age',             900000000,     1500000000,    'WARNING', true),
  (40, 13, 'Oldest datfrozenxid age',             1500000000,     2200000000,    'ALERT',   true),
  (41, 14, 'Oldest datminmxid age',               0,             900000000,     'OK',      false),
  (42, 14, 'Oldest datminmxid age',               900000000,     1500000000,    'WARNING', true),
  (43, 14, 'Oldest datminmxid age',               1500000000,    2200000000,    'ALERT',   true),
  -- 15: an orphaned 2PC pins xmin forever and drives 13/14 upward.
  (44, 15, 'Oldest prepared xact (minutes)',      0,             5,             'OK',      false),
  (45, 15, 'Oldest prepared xact (minutes)',      5,             60,            'WARNING', true),
  (46, 15, 'Oldest prepared xact (minutes)',      60,            999999999,     'ALERT',   true),
  -- 16: leading indicator for check 10. wal_status='lost' means slot is dead.
  (47, 16, 'Unhealthy replication slots',         0,             1,             'OK',      false),
  (48, 16, 'Unhealthy replication slots',         1,             999999,        'ALERT',   true),
  -- 17: inverted. Set the boundary to your actual replica count.
  (49, 17, 'Streaming standbys connected',        0,             1,             'ALERT',   true),
  (50, 17, 'Streaming standbys connected',        1,             999999,        'OK',      false),
  -- 18: enabled subscription with no apply worker = replication silently stopped.
  (51, 18, 'Subscriptions without worker',        0,             1,             'OK',      false),
  (52, 18, 'Subscriptions without worker',        1,             999999,        'ALERT',   true),
  -- 20: backlog depth beats "minutes since last failure" as a signal.
  (53, 20, 'WAL archive backlog (.ready files)',  0,             100,           'OK',      false),
  (54, 20, 'WAL archive backlog (.ready files)',  100,           1000,          'WARNING', true),
  (55, 20, 'WAL archive backlog (.ready files)',  1000,          999999999,     'ALERT',   true),
  -- 21: leftovers from failed CREATE INDEX CONCURRENTLY / REINDEX CONCURRENTLY.
  (56, 21, 'Invalid indexes',                     0,             1,             'OK',      false),
  (57, 21, 'Invalid indexes',                     1,             999999,        'WARNING', false),
  -- 24: saturation as a pct survives max_connections changes, unlike check 1.
  (58, 24, 'Connection slots used (pct)',         0,             70,            'OK',      false),
  (59, 24, 'Connection slots used (pct)',         70,            85,            'WARNING', true),
  (60, 24, 'Connection slots used (pct)',         85,            101,           'ALERT',   true),
  -- 26: check 9 reads pg_stat_replication, which is empty on a standby.
  (61, 26, 'Standby replay age (seconds)',        0,             300,           'OK',      false),
  (62, 26, 'Standby replay age (seconds)',        300,           1800,          'WARNING', true),
  (63, 26, 'Standby replay age (seconds)',        1800,          999999999,     'ALERT',   true);

UPDATE dba.alert_state_config SET role_scope = 'primary' WHERE check_id = 17;
UPDATE dba.alert_state_config SET role_scope = 'standby' WHERE check_id = 26;
UPDATE dba.alert_state_config SET is_set     = true      WHERE check_id IN (9, 10);

SELECT setval(pg_get_serial_sequence('dba.alert_state_config','id'),
              (SELECT max(id) FROM dba.alert_state_config));


-- Values pushed in from outside the database (checks 11 and 12).
-- Collector:
--   INSERT INTO dba.external_check (check_id, value, notes)
--   VALUES (11, 63, 'PGDATA')
--   ON CONFLICT (check_id) DO UPDATE
--     SET value = EXCLUDED.value, notes = EXCLUDED.notes, updated_at = now();
CREATE TABLE IF NOT EXISTS dba.external_check (
    check_id   integer PRIMARY KEY,
    value      bigint  NOT NULL,
    notes      text,
    updated_at timestamptz NOT NULL DEFAULT now()
);


-- Temporary suppression of notifications for a check. Rows expire on their
-- own, so nothing stays muted by accident. max_value lets a known-bad value be
-- silenced while an escalation beyond it still breaks through.
DROP TABLE IF EXISTS dba.alert_silence CASCADE;

CREATE TABLE IF NOT EXISTS dba.alert_silence (
    check_id   integer PRIMARY KEY,
    until      timestamptz NOT NULL,
    max_value  bigint,                 -- NULL = silence at any value
    reason     text NOT NULL,
    created_by text NOT NULL DEFAULT current_user,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT silence_in_future CHECK (until > created_at)
);

COMMENT ON TABLE dba.alert_silence IS
    'Notification suppression. dba.alert_state still shows the true state; only the alerter stays quiet.';


-- Every scalar branch below must return exactly one row, always. A branch that
-- returns NULL or no rows makes the check vanish from the output rather than
-- report OK, which reads as "healthy" on every dashboard.
CREATE VIEW dba.alert_state AS
WITH act AS (
    SELECT
      count(*) FILTER (WHERE backend_type = 'client backend'
                         AND state IS DISTINCT FROM 'idle')                   AS non_idle,
      count(*) FILTER (WHERE wait_event_type = 'LWLock')                      AS lwlocks,
      count(*) FILTER (WHERE wait_event_type = 'Lock'
                         AND (backend_type = 'autovacuum worker'
                              OR query ~* '^\s*(vacuum|analyze)\M'))          AS vac_blocked,
      count(*) FILTER (WHERE wait_event_type = 'Lock')                        AS blocked,
      max(now() - xact_start) FILTER (WHERE state = 'idle in transaction')    AS idle_age,
      (array_agg(pid ORDER BY xact_start)
         FILTER (WHERE state = 'idle in transaction'))[1]                     AS idle_pid,
      max(now() - xact_start) FILTER (WHERE state = 'active'
                                        AND xact_start IS NOT NULL)           AS act_age,
      (array_agg(pid ORDER BY xact_start)
         FILTER (WHERE state = 'active' AND xact_start IS NOT NULL))[1]       AS act_pid
    FROM pg_stat_activity
), check_results AS (
    SELECT v.check_id, v.value, v.notes
    FROM act a
    CROSS JOIN LATERAL (VALUES
        (1, a.non_idle,    NULL::text),
        (2, a.lwlocks,     NULL),
        (3, a.vac_blocked, NULL),
        (4, a.blocked,     NULL),
        (6, coalesce((extract(epoch FROM a.idle_age) / 60)::bigint, 0), 'pid: ' || a.idle_pid),
        (7, coalesce((extract(epoch FROM a.act_age)  / 60)::bigint, 0), 'pid: ' || a.act_pid)
    ) AS v(check_id, value, notes)

    UNION ALL
    SELECT 5, count(*), NULL FROM pg_locks

    -- last_failed_time is NULL when archiving has never failed.
    UNION ALL
    SELECT 8, coalesce((extract(epoch FROM now() - last_failed_time) / 60)::bigint,
                       999999998), NULL
    FROM pg_stat_archiver

    UNION ALL
    SELECT 9, seconds_behind, replica || ' (' || client || ')'
    FROM dba.public_replication_lag()

    -- pg_current_wal_insert_lsn() throws on a standby and would fail the whole
    -- view, not just this check.
    UNION ALL
    SELECT 10,
           pg_wal_lsn_diff(CASE WHEN pg_is_in_recovery()
                                THEN pg_last_wal_replay_lsn()
                                ELSE pg_current_wal_insert_lsn() END,
                           restart_lsn)::bigint,
           slot_name
    FROM pg_replication_slots
    WHERE restart_lsn IS NOT NULL

    UNION ALL
    SELECT check_id, value, notes
    FROM dba.external_check
    WHERE updated_at > now() - interval '10 minutes'   -- stale collector != OK

    UNION ALL
    SELECT 13, max(age(datfrozenxid))::bigint,
           (array_agg(datname ORDER BY age(datfrozenxid) DESC))[1]
    FROM pg_database WHERE datallowconn

    UNION ALL
    SELECT 14, max(mxid_age(datminmxid))::bigint,
           (array_agg(datname ORDER BY mxid_age(datminmxid) DESC))[1]
    FROM pg_database WHERE datallowconn

    UNION ALL
    SELECT 15, coalesce(max(extract(epoch FROM now() - prepared) / 60)::bigint, 0),
           (array_agg(gid ORDER BY prepared))[1]
    FROM pg_prepared_xacts

    UNION ALL
    SELECT 16, count(*)::bigint,
           string_agg(slot_name || '=' || wal_status
                      || CASE WHEN active THEN '' ELSE '/inactive' END, ', ')
    FROM pg_replication_slots
    -- 'extended' is normal when long transactions hold the slot back; size is
    -- covered by check 10. Only genuinely at-risk states belong here.
    WHERE NOT active OR wal_status IN ('unreserved','lost')

    UNION ALL
    SELECT 17, count(*)::bigint, string_agg(application_name, ',')
    FROM pg_stat_replication WHERE state = 'streaming'

    UNION ALL
    SELECT 18, count(*)::bigint, string_agg(s.subname, ',')
    FROM pg_subscription s
    WHERE s.subenabled
      AND NOT EXISTS (SELECT 1 FROM pg_stat_subscription ss
                      WHERE ss.subid = s.oid AND ss.pid IS NOT NULL)

    UNION ALL
    SELECT 20, count(*)::bigint, NULL
    FROM pg_ls_archive_statusdir() WHERE name LIKE '%.ready'

    UNION ALL
    SELECT 21, count(*)::bigint,
           left(string_agg(indexrelid::regclass::text, ','), 200)
    FROM pg_index WHERE NOT indisvalid

    UNION ALL
    SELECT 24, (100 * count(*) / current_setting('max_connections')::int)::bigint, NULL
    FROM pg_stat_activity

    UNION ALL
    SELECT 26, CASE WHEN pg_is_in_recovery()
                    THEN extract(epoch FROM now() - pg_last_xact_replay_timestamp())::bigint
               END, NULL
)
SELECT rs.check_id,
       cfg.id                AS config_id,
       now()::timestamptz(0) AS date,
       cfg.description,
       cfg.alert_type        AS state,
       rs.value              AS current_value,
       rs.notes,
       format('%s-%s', cfg.threshold_min, cfg.threshold_high) AS threshold,
       cfg.will_page,
       -- Appended, not inserted: CREATE OR REPLACE VIEW can add columns at the
       -- end but cannot reorder or rename existing ones.
       (sil.check_id IS NOT NULL
        AND (sil.max_value IS NULL OR rs.value <= sil.max_value)) AS silenced,
       sil.until  AS silenced_until,
       sil.reason AS silence_reason
FROM check_results rs
JOIN dba.alert_state_config cfg
  ON cfg.check_id = rs.check_id
 AND int8range(cfg.threshold_min, cfg.threshold_high) @> rs.value
 AND (cfg.role_scope = 'any'
      OR cfg.role_scope = CASE WHEN pg_is_in_recovery() THEN 'standby' ELSE 'primary' END)
LEFT JOIN dba.alert_silence sil
  ON sil.check_id = rs.check_id AND sil.until > now();

COMMENT ON VIEW dba.alert_state IS
    'Current value of every check joined to its threshold band. Timestamps are timestamptz - render in the reporting timezone at display time.';


-- Meta-check: config bands that no branch above feeds. Alert on non-empty.
CREATE VIEW dba.alert_state_missing AS
SELECT DISTINCT c.check_id, c.description
FROM dba.alert_state_config c
WHERE NOT c.is_set
  AND (c.role_scope = 'any'
       OR c.role_scope = CASE WHEN pg_is_in_recovery() THEN 'standby' ELSE 'primary' END)
  AND NOT EXISTS (SELECT 1 FROM dba.alert_state a WHERE a.check_id = c.check_id);

COMMENT ON VIEW dba.alert_state_missing IS
    'Checks with configured thresholds but no producer. Non-empty means a check is silently absent, not healthy.';


CREATE OR REPLACE VIEW dba.alert_silenced AS
SELECT s.check_id, c.description, s.reason, s.created_by, s.created_at,
       s.until, s.max_value, (s.until - now())::interval(0) AS expires_in
FROM dba.alert_silence s
LEFT JOIN LATERAL (SELECT description FROM dba.alert_state_config
                   WHERE check_id = s.check_id LIMIT 1) c ON true
WHERE s.until > now()
ORDER BY s.until;

create OR REPLACE view dba.state as 
  SELECT check_id, date, description, state, current_value, notes
   FROM dba.alert_state
  ORDER BY check_id;

COMMENT ON VIEW dba.state IS
    'Simplified view of alert_state';

create OR REPLACE  view dba.xid_age as 
SELECT COALESCE(pt.oid, c.oid)::regclass                AS relation,
       CASE c.relkind WHEN 'r' THEN 'table'
                      WHEN 'm' THEN 'matview'
                      WHEN 't' THEN 'toast' END         AS kind,
       age(c.relfrozenxid)                              AS xid_age,
       mxid_age(c.relminmxid)                           AS mxid_age,
       pg_size_pretty(pg_relation_size(c.oid))          AS size,
       s.last_vacuum, s.last_autovacuum, s.n_dead_tup
FROM pg_class c
LEFT JOIN pg_class pt ON pt.reltoastrelid = c.oid
LEFT JOIN pg_stat_all_tables s ON s.relid = c.oid
WHERE c.relkind IN ('r','m','t')
  AND age(c.relfrozenxid) > 50000000
ORDER BY age(c.relfrozenxid) DESC, pg_relation_size(c.oid) DESC;

COMMENT ON VIEW dba.xid_age IS
    'Monitors which tables keeping the oldest xid';


-- ============================================================================
-- grants
-- ============================================================================

GRANT USAGE ON SCHEMA dba TO pg_monitor;
GRANT SELECT ON ALL TABLES IN SCHEMA dba TO pg_monitor;
ALTER DEFAULT PRIVILEGES IN SCHEMA dba GRANT SELECT ON TABLES TO pg_monitor;
