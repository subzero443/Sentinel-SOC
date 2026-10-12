"""Sentinel SOC: local educational incident response dashboard.

Accepts normalized events or limited Linux auth.log / Windows Event JSON.
Not a production SIEM. Public mode is strictly read-only and synthetic.
"""
from __future__ import annotations
import csv
import io
import json
import os
import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

import yaml
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get('SOC_DB_PATH', str(ROOT / 'soc.db')))
RULES = ROOT / 'rules'
PUBLIC_DEMO = os.environ.get('SOC_PUBLIC_DEMO', '0').lower() in {'1', 'true', 'yes'}
FRONTEND_DIST = ROOT.parent / 'frontend' / 'dist'
app = FastAPI(title='Sentinel SOC API', version='1.0.0')
app.add_middleware(CORSMiddleware, allow_origins=['http://localhost:5173', 'http://127.0.0.1:5173'], allow_methods=['*'], allow_headers=['*'])

@app.middleware('http')
async def protect_public_demo(request, call_next):
    # The public instance intentionally allows only non-mutating requests.
    # It is a portfolio demonstration, never a place for real security logs.
    if PUBLIC_DEMO and request.method not in {'GET', 'HEAD', 'OPTIONS'}:
        return JSONResponse(status_code=403, content={'detail': 'Public portfolio demo is read-only.'})
    return await call_next(request)

class EventIn(BaseModel):
    timestamp: datetime
    source: str = Field(default='generic', max_length=80)
    username: str = Field(default='unknown', max_length=120)
    source_ip: str = Field(default='unknown', max_length=100)
    outcome: Literal['success', 'failure']
    raw: str = Field(default='', max_length=2000)

class NoteIn(BaseModel):
    note: str = Field(min_length=1, max_length=2000)
    analyst: str = Field(default='Demo Analyst', max_length=80)

class StatusIn(BaseModel):
    status: Literal['open', 'investigating', 'resolved', 'false_positive']

def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT, username TEXT, source_ip TEXT, outcome TEXT, raw TEXT);
        CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE, rule TEXT, severity TEXT, source_ip TEXT, username TEXT, event_count INTEGER, first_seen TEXT, last_seen TEXT, status TEXT DEFAULT 'open', explanation TEXT);
        CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY, alert_id TEXT NOT NULL, analyst TEXT, note TEXT, created_at TEXT, FOREIGN KEY(alert_id) REFERENCES alerts(id));
        ''')
init_db()

def utc(dt: datetime):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def load_rules():
    return [yaml.safe_load(p.read_text(encoding='utf8')) for p in sorted(RULES.glob('*.yml'))]

def evaluate(conn):
    """Rebuild demo correlation alerts while preserving status/notes for same fingerprints."""
    rows = [dict(x) for x in conn.execute('SELECT * FROM events ORDER BY timestamp ASC')]
    groups = defaultdict(list)
    for row in rows:
        groups[row['source_ip']].append(row)
    for rule in load_rules():
        cfg = rule['x_demo_correlation']
        minutes = cfg['window_minutes']
        for ip, events in groups.items():
            for idx, event in enumerate(events):
                t = datetime.fromisoformat(event['timestamp'])
                recent = [x for x in events[:idx+1] if t - timedelta(minutes=minutes) <= datetime.fromisoformat(x['timestamp']) <= t]
                failures = [x for x in recent if x['outcome'] == 'failure']
                if 'threshold' in cfg:
                    triggered = event['outcome'] == 'failure' and len(failures) >= cfg['threshold']
                    related = failures
                else:
                    preceding = [x for x in failures if x['timestamp'] < event['timestamp']]
                    triggered = event['outcome'] == 'success' and len(preceding) >= cfg['preceding_failures']
                    related = preceding + [event]
                if not triggered:
                    continue
                # Fingerprint one alert per rule/IP/10 or 15 minute bucket. Duplicate events don't create duplicate alerts.
                bucket = int(t.timestamp()) // (minutes * 60)
                fingerprint = f"{rule['id']}:{ip}:{bucket}"
                start = related[0]['timestamp']
                detail = f"{len(failures)} failed sign-ins observed from {ip} in a {minutes}-minute window."
                if 'preceding_failures' in cfg:
                    detail = f"Successful sign-in for {event['username']} after {len(preceding)} failed attempts from {ip}. Investigate account activity."
                conn.execute('''INSERT INTO alerts (id,fingerprint,rule,severity,source_ip,username,event_count,first_seen,last_seen,explanation)
                VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET event_count=excluded.event_count,last_seen=excluded.last_seen,explanation=excluded.explanation''',
                (str(uuid4()), fingerprint, rule['title'], rule['level'], ip, event['username'], len(related), start, event['timestamp'], detail))

def ingest(events: list[EventIn]):
    if len(events) > 5000:
        raise HTTPException(413, 'Maximum 5000 events per request')
    with db() as conn:
        for event in events:
            conn.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?)', (str(uuid4()), utc(event.timestamp), event.source, event.username, event.source_ip, event.outcome, event.raw))
        evaluate(conn)
    return {'ingested': len(events)}

@app.get('/api/health')
def health():
    return {'status': 'ok', 'rules': len(load_rules())}

@app.get('/api/overview')
def overview():
    with db() as conn:
        total = conn.execute('SELECT count(*) FROM events').fetchone()[0]
        alerts = conn.execute('SELECT count(*) FROM alerts').fetchone()[0]
        critical = conn.execute("SELECT count(*) FROM alerts WHERE severity='critical' AND status NOT IN ('resolved','false_positive')").fetchone()[0]
        failures = conn.execute("SELECT count(*) FROM events WHERE outcome='failure'").fetchone()[0]
        trend = [dict(x) for x in conn.execute("SELECT substr(timestamp,1,10) day, count(*) count FROM events GROUP BY day ORDER BY day DESC LIMIT 14")]
    return {'events': total, 'alerts': alerts, 'critical': critical, 'failures': failures, 'trend': list(reversed(trend))}

@app.get('/api/events')
def list_events(limit: int = 100):
    with db() as conn:
        return [dict(x) for x in conn.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?', (min(max(limit,1),500),))]

@app.post('/api/events')
def add_events(events: list[EventIn]):
    return ingest(events)

@app.get('/api/alerts')
def list_alerts():
    with db() as conn:
        return [dict(x) for x in conn.execute('SELECT * FROM alerts ORDER BY last_seen DESC')]

@app.get('/api/alerts/{alert_id}')
def alert_detail(alert_id: str):
    with db() as conn:
        row = conn.execute('SELECT * FROM alerts WHERE id=?', (alert_id,)).fetchone()
        if not row:
            raise HTTPException(404, 'Alert not found')
        notes = [dict(x) for x in conn.execute('SELECT * FROM notes WHERE alert_id=? ORDER BY created_at DESC', (alert_id,))]
        return {'alert': dict(row), 'notes': notes}

@app.patch('/api/alerts/{alert_id}')
def update_alert(alert_id: str, data: StatusIn):
    with db() as conn:
        result = conn.execute('UPDATE alerts SET status=? WHERE id=?', (data.status, alert_id))
        if result.rowcount == 0:
            raise HTTPException(404, 'Alert not found')
    return {'ok': True}

@app.post('/api/alerts/{alert_id}/notes')
def add_note(alert_id: str, data: NoteIn):
    with db() as conn:
        if not conn.execute('SELECT 1 FROM alerts WHERE id=?', (alert_id,)).fetchone():
            raise HTTPException(404, 'Alert not found')
        conn.execute('INSERT INTO notes VALUES (?,?,?,?,?)', (str(uuid4()), alert_id, data.analyst, data.note, utc(datetime.now(timezone.utc))))
    return {'ok': True}

@app.get('/api/alerts/{alert_id}/report')
def report(alert_id: str):
    detail = alert_detail(alert_id)
    a = detail['alert']
    content = f"# Incident Report: {a['rule']}\n\n- Alert ID: {a['id']}\n- Severity: {a['severity']}\n- Status: {a['status']}\n- Source IP: {a['source_ip']}\n- First seen: {a['first_seen']}\n- Last seen: {a['last_seen']}\n\n## Evidence\n{a['explanation']}\n\n## Analyst notes\n"
    content += '\n'.join(f"- {n['created_at']} ({n['analyst']}): {n['note']}" for n in detail['notes']) or '- No notes yet.'
    content += '\n\n## Limitations\nThis is a synthetic/demo alert. Validate against original logs before drawing conclusions.\n'
    return StreamingResponse(io.BytesIO(content.encode()), media_type='text/markdown', headers={'Content-Disposition': f'attachment; filename="incident-{alert_id[:8]}.md"'})

@app.get('/api/rules')
def rules():
    return load_rules()

@app.post('/api/demo/reset')
def reset_demo():
    with db() as conn:
        conn.execute('DELETE FROM notes')
        conn.execute('DELETE FROM alerts')
        conn.execute('DELETE FROM events')
    return {'ok': True}

@app.post('/api/demo/seed')
def seed_demo():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    events = []
    for i in range(9):
        events.append(EventIn(timestamp=now-timedelta(minutes=9-i), source='linux:sshd', username='admin', source_ip='203.0.113.42', outcome='failure', raw='Synthetic SSH failed password'))
    events.append(EventIn(timestamp=now, source='linux:sshd', username='admin', source_ip='203.0.113.42', outcome='success', raw='Synthetic SSH accepted password'))
    for i in range(4):
        events.append(EventIn(timestamp=now-timedelta(minutes=3-i), source='windows:4625', username='guest', source_ip='198.51.100.18', outcome='failure', raw='Synthetic Windows logon failure'))
    for i in range(12):
        events.append(EventIn(timestamp=now-timedelta(minutes=i*13), source='windows:4624', username='employee', source_ip='192.0.2.10', outcome='success', raw='Synthetic normal sign-in'))
    return ingest(events)

LINUX_RE = re.compile(r'(Failed password|Accepted password).*?for (?:invalid user )?(\S+) from ([\da-fA-F:.]+)', re.I)
@app.post('/api/import')
async def import_logs(file: UploadFile = File(...)):
    raw = await file.read(1024*1024+1)
    if len(raw) > 1024*1024:
        raise HTTPException(413, 'Maximum file size 1 MB')
    try:
        content = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise HTTPException(400, 'UTF-8 text files only')
    events = []
    if (file.filename or '').endswith('.json'):
        try:
            data = json.loads(content)
            if not isinstance(data, list): raise ValueError('Expected JSON array')
            for item in data:
                if 'EventID' in item:
                    event_id = int(item['EventID'])
                    if event_id not in (4624, 4625): continue
                    events.append(EventIn(timestamp=item['timestamp'], source='windows:'+str(event_id), username=item.get('TargetUserName','unknown'), source_ip=item.get('IpAddress','unknown'), outcome='success' if event_id == 4624 else 'failure', raw=json.dumps(item)[:2000]))
                else:
                    events.append(EventIn(**item))
        except (ValueError, TypeError, KeyError) as e:
            raise HTTPException(400, f'Invalid JSON events: {str(e)[:160]}')
    elif (file.filename or '').endswith(('.log','.txt')):
        # Linux syslog has no year; use current UTC year and month/day/time from the line.
        for line in content.splitlines():
            m = LINUX_RE.search(line)
            if not m: continue
            try:
                dt = datetime.strptime(f'{datetime.now(timezone.utc).year} {line[:15]}', '%Y %b %d %H:%M:%S').replace(tzinfo=timezone.utc)
            except ValueError: continue
            events.append(EventIn(timestamp=dt, source='linux:sshd', username=m.group(2), source_ip=m.group(3), outcome='failure' if m.group(1).lower().startswith('failed') else 'success', raw=line[:2000]))
    else:
        raise HTTPException(400, 'Upload .json, .log, or .txt')
    return ingest(events)


@app.on_event('startup')
def prepare_public_demo():
    # Render Free has ephemeral storage. Regenerate fictional examples after restarts.
    if PUBLIC_DEMO:
        with db() as conn:
            event_count = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        if event_count == 0:
            seed_demo()  # Internal call; HTTP write endpoints remain blocked.

# In production the compiled React files live alongside this FastAPI service.
# Existing /api routes take precedence because the static mount comes last.
if FRONTEND_DIST.exists():
    app.mount('/', StaticFiles(directory=str(FRONTEND_DIST), html=True), name='frontend')
