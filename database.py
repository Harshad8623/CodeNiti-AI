"""SQLite persistence with user-level authorization, session revocation and privacy controls."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from config import settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def connect():
    path = Path(settings.database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys=ON')
    connection.execute('PRAGMA busy_timeout=10000')
    return connection


def init_db():
    with connect() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                display_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                tool TEXT NOT NULL, language TEXT NOT NULL,
                code TEXT NOT NULL DEFAULT '', code2 TEXT NOT NULL DEFAULT '',
                prompt TEXT NOT NULL DEFAULT '', result TEXT NOT NULL,
                engine TEXT NOT NULL, cache_key TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_history_user ON history(user_id, id DESC);
            CREATE TABLE IF NOT EXISTS response_cache (
                key TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                result TEXT NOT NULL, engine TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cache_user ON response_cache(user_id);
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                tool TEXT NOT NULL, engine TEXT NOT NULL,
                cached INTEGER NOT NULL, duration_ms REAL NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_metrics_user ON metrics(user_id,id DESC);
            CREATE TABLE IF NOT EXISTS ai_quota (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                day TEXT NOT NULL, requests INTEGER NOT NULL,
                PRIMARY KEY (user_id, day)
            );
        ''')
        # Migration: ensure cache_key column exists for existing databases
        cols = [r['name'] for r in db.execute('PRAGMA table_info(history)').fetchall()]
        if 'cache_key' not in cols:
            db.execute("ALTER TABLE history ADD COLUMN cache_key TEXT NOT NULL DEFAULT ''")


def fingerprint(user_id: int, payload: dict) -> str:
    text = json.dumps({'user_id': user_id, **payload}, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(text.encode()).hexdigest()


def cache_get(key: str, user_id: int):
    with connect() as db:
        row = db.execute('SELECT result,engine FROM response_cache WHERE key=? AND user_id=? AND expires_at>?',
                         (key,user_id,utcnow().isoformat())).fetchone()
        return dict(row) if row else None


def cache_put(key: str, user_id: int, result: str, engine: str):
    expiry = (utcnow() + timedelta(seconds=settings.cache_ttl)).isoformat()
    with connect() as db:
        db.execute('INSERT OR REPLACE INTO response_cache(key,user_id,result,engine,expires_at) VALUES (?,?,?,?,?)',
                   (key,user_id,result,engine,expiry))


def save_history(user_id: int, tool: str, language: str, code: str, code2: str,
                 prompt: str, result: str, engine: str, cache_key: str = ''):
    with connect() as db:
        db.execute('''INSERT INTO history(user_id,tool,language,code,code2,prompt,result,engine,cache_key,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)''',
                   (user_id,tool,language,code,code2,prompt,result,engine,cache_key,utcnow().isoformat()))
        db.execute('''DELETE FROM history WHERE user_id=? AND id NOT IN (
                   SELECT id FROM history WHERE user_id=? ORDER BY id DESC LIMIT 100)''',(user_id,user_id))


def list_history(user_id: int, limit: int = 30):
    with connect() as db:
        rows = db.execute('''SELECT id,tool,language,code,code2,prompt,result,engine,created_at
                             FROM history WHERE user_id=? ORDER BY id DESC LIMIT ?''',(user_id,limit)).fetchall()
        return [dict(row) for row in rows]


def remove_history(user_id: int, item_id: int) -> bool:
    with connect() as db:
        row = db.execute('SELECT cache_key FROM history WHERE user_id=? AND id=?', (user_id, item_id)).fetchone()
        if row and row['cache_key']:
            ck = row['cache_key']
            db.execute('DELETE FROM response_cache WHERE key=? AND user_id=?', (ck, user_id))
            from services.cache import cache
            cache.delete(ck)
        return db.execute('DELETE FROM history WHERE user_id=? AND id=?',(user_id,item_id)).rowcount > 0


def clear_history(user_id: int):
    with connect() as db:
        db.execute('DELETE FROM history WHERE user_id=?',(user_id,))
        db.execute('DELETE FROM response_cache WHERE user_id=?',(user_id,))


def clear_account(user_id: int):
    with connect() as db:
        db.execute('DELETE FROM users WHERE id=?',(user_id,))


def record_metric(user_id: int, tool: str, engine: str, cached: bool, duration_ms: float):
    with connect() as db:
        db.execute('INSERT INTO metrics(user_id,tool,engine,cached,duration_ms,created_at) VALUES (?,?,?,?,?,?)',
                   (user_id,tool,engine,int(cached),duration_ms,utcnow().isoformat()))
        # User-level metrics are bounded; store no code or prompts.
        db.execute('''DELETE FROM metrics WHERE user_id=? AND id NOT IN (
                   SELECT id FROM metrics WHERE user_id=? ORDER BY id DESC LIMIT 2000)''',(user_id,user_id))


def take_ai_quota(user_id: int) -> tuple[bool,int]:
    """Reserve one AI request atomically, including failed provider calls, to prevent abuse."""
    day = utcnow().date().isoformat()
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('INSERT OR IGNORE INTO ai_quota(user_id,day,requests) VALUES (?,?,0)',(user_id,day))
        changed = db.execute('UPDATE ai_quota SET requests=requests+1 WHERE user_id=? AND day=? AND requests<?',
                             (user_id,day,settings.ai_daily_limit)).rowcount
        current = db.execute('SELECT requests FROM ai_quota WHERE user_id=? AND day=?',(user_id,day)).fetchone()[0]
        return bool(changed), max(0,settings.ai_daily_limit-current)


def workspace_stats(user_id: int):
    with connect() as db:
        saved = db.execute('SELECT COUNT(*),COUNT(DISTINCT tool) FROM history WHERE user_id=?',(user_id,)).fetchone()
        samples = db.execute('SELECT cached,duration_ms FROM metrics WHERE user_id=? ORDER BY id DESC LIMIT 500',(user_id,)).fetchall()
        remaining_row = db.execute('SELECT requests FROM ai_quota WHERE user_id=? AND day=?',
                                   (user_id,utcnow().date().isoformat())).fetchone()
    durations = sorted(float(x['duration_ms']) for x in samples)
    hits = sum(x['cached'] for x in samples)
    cold = [float(x['duration_ms']) for x in samples if not x['cached']]
    warm = [float(x['duration_ms']) for x in samples if x['cached']]
    average = lambda nums: round(sum(nums)/len(nums),2) if nums else None
    cold_avg, warm_avg = average(cold), average(warm)
    return {
        'saved_analyses':saved[0], 'tools_used':saved[1], 'requests_total':len(samples),
        'cache_hits':hits, 'cache_hit_rate_percent':round(100*hits/len(samples),1) if samples else 0,
        'average_latency_ms':average(durations),
        'p95_latency_ms':round(durations[max(0,__import__('math').ceil(len(durations)*.95)-1)],2) if durations else None,
        'average_cold_ms':cold_avg, 'average_cached_ms':warm_avg,
        'latency_reduction_percent':round((cold_avg-warm_avg)/cold_avg*100,1) if cold_avg and warm_avg is not None else None,
        'ai_remaining_today':max(0,settings.ai_daily_limit-(remaining_row[0] if remaining_row else 0)),
        'sample_size':len(samples),
    }
