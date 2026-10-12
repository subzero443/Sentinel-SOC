import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
os.environ['SOC_DB_PATH'] = str(Path(tempfile.mkdtemp()) / 'test.db')
from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)

def test_detection_and_workflow():
    client.post('/api/demo/reset')
    t = datetime.now(timezone.utc)
    events = [{'timestamp': (t+timedelta(seconds=i)).isoformat(), 'source':'test','username':'admin','source_ip':'203.0.113.7','outcome':'failure'} for i in range(5)]
    assert client.post('/api/events', json=events).status_code == 200
    alerts = client.get('/api/alerts').json()
    assert any(x['severity']=='high' for x in alerts)
    aid = alerts[0]['id']
    assert client.post(f'/api/alerts/{aid}/notes',json={'note':'Checked authorized lab logs'}).status_code == 200
    assert client.patch(f'/api/alerts/{aid}',json={'status':'false_positive'}).status_code == 200
    assert client.get(f'/api/alerts/{aid}/report').status_code == 200

def test_no_false_positive_for_normal_logins():
    client.post('/api/demo/reset')
    t = datetime.now(timezone.utc)
    assert client.post('/api/events',json=[{'timestamp':t.isoformat(),'source_ip':'192.0.2.1','outcome':'success'}]).status_code == 200
    assert client.get('/api/alerts').json() == []
