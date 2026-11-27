import io, os, tempfile
os.environ["MZ_DB"] = os.path.join(tempfile.mkdtemp(), "s.db"); os.environ["MZ_DIST"] = tempfile.mkdtemp()
open(os.path.join(os.environ["MZ_DIST"], "index.html"), "w").write("<html><head></head><body></body></html>")
import httpx
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
import safety
from app import app
import app as appmod

fake = FastAPI(); seen = []          # a stand-in for the safety service: it only has to honour the documented contract
@fake.get("/api/health")
def h(): return {"ok": True, "gateway": 2}
@fake.post("/api/gateway/submit")
async def submit(r: Request):
    b = await r.json(); seen.append(b); t = (b["text"] + " " + ((b.get("media") or {}).get("transcript") or "")).lower()
    if "nitakuua" in t: return {"decision": "block", "category": "threat", "severity": 3, "language": "sw", "attempt_id": 7, "persisted": False, "standing": {"status": "watch"}, "warning": {"title": "Message not sent"}, "notice": {"id": 1, "sender_id": b["sender_id"], "sender_name": b["sender_name"], "category": "threat", "media": "text", "count": 1, "state": "new"}}
    if "soft" in t and not b["acknowledged"]: return {"decision": "warn", "category": "degradation", "message": "careful"}
    if "trusted" in t: return {"decision": "deliver_trusted", "category": "threat"}
    return {"decision": "deliver", "category": "none"}
@fake.get("/api/gateway/notices")
def notices(user_id: str): return [{"id": 1, "sender_id": "ben", "sender_name": "ben", "category": "threat", "media": "text", "count": 1, "state": "new"}]
@fake.get("/api/gateway/trust")
def trust(user_id: str): return []
@fake.post("/api/gateway/reports")
async def rep(r: Request): return {"ref": "ARC-0001", "status": "submitted"}

safety.TRANSPORT = httpx.ASGITransport(app=fake)
c = TestClient(app); pushed = []
async def fake_push(names, payload): pushed.append((sorted(set(names)), payload))     # the test client cannot deliver between two open sockets, so capture pushes
def reg(n):
    r = c.post("/api/register", json={"name": n, "password": "secret123"})
    return (r if r.status_code == 200 else c.post("/api/login", json={"name": n, "password": "secret123"})).json()["token"]
import pytest
@pytest.fixture(autouse=True)
def _patch_push():
    old = appmod.push; appmod.push = fake_push; pushed.clear(); yield; appmod.push = old
def wait(t, who=None):
    import time
    for _ in range(100):
        for names, p in pushed:
            if p.get("type") == t and (who is None or who in names): pushed.remove((names, p)); return p
        time.sleep(0.03)
    raise AssertionError("no " + t)

def test_blocked_message_is_not_delivered_and_receiver_is_noticed():
    ta, tb = reg("ann"), reg("ben"); H = {"Authorization": "Bearer " + ta}
    assert c.put("/api/admin/safety", json={"url": "http://archer.test", "key": "sk_x", "enabled": True}, headers=H).json()["enabled"]
    assert c.post("/api/admin/safety/test", headers=H).json() == {"reachable": True, "gateway": True, "key_ok": True}
    conv = "dm:ann|ben"
    with c.websocket_connect("/ws?token=" + ta) as wa:
        wa.send_json({"type": "msg", "conv": conv, "text": "Nitakuua ukinipuuza", "lang": "sw"})
        b = wait("blocked", "ann"); assert b["category"] == "threat" and b["warning"]["title"] == "Message not sent" and "notice" not in b
        n = wait("notice", "ben"); assert n["notice"]["sender_name"] == "ann"
        assert c.get(f"/api/conv/{conv}/messages", headers={"Authorization": "Bearer " + tb}).json() == []        # never delivered
        wa.send_json({"type": "msg", "conv": conv, "text": "tuonane kesho"}); assert wait("msg", "ben")["text"] == "tuonane kesho"
        wa.send_json({"type": "msg", "conv": conv, "text": "soft insult"}); assert wait("warn", "ann")["message"] == "careful"
        wa.send_json({"type": "msg", "conv": conv, "text": "soft insult", "ack": True}); assert wait("msg", "ben")["text"] == "soft insult"      # sender chose to send after the warning
        wa.send_json({"type": "msg", "conv": conv, "text": "trusted one"}); assert wait("msg", "ben")["flag"].startswith("threat")                       # delivered, labelled
    assert seen[0]["lang"] == "sw" and seen[0]["sender_id"] == "ann" and seen[0]["receiver_id"] == "ben"

def test_voice_note_transcript_is_sent_for_screening_and_fails_open():
    ta, tb = reg("vic"), reg("val"); H = {"Authorization": "Bearer " + ta}
    up = c.post("/api/upload", files={"file": ("v.webm", io.BytesIO(b"abc"), "audio/webm")}, headers=H).json(); assert up["kind"] == "voice"
    path = os.path.join(appmod.UP, os.path.basename(up["url"])); assert os.path.exists(path)
    with c.websocket_connect("/ws?token=" + ta) as wa:
        wa.send_json({"type": "msg", "conv": "dm:val|vic", "text": "", "media": up, "transcript": "ntakumaliza, nitakuua"}); wait("blocked", "vic")
        assert not os.path.exists(path)                                                                      # blocked media is removed from the platform
        safety.TRANSPORT = httpx.ASGITransport(app=FastAPI())                                                # service broken -> deliver (fail open)
        wa.send_json({"type": "msg", "conv": "dm:val|vic", "text": "habari"}); assert wait("msg", "val")["text"] == "habari"
    safety.TRANSPORT = httpx.ASGITransport(app=fake)

def test_safety_proxy_needs_login_and_admin_for_settings():
    assert c.get("/api/safety/notices").status_code == 401
    t = reg("zed"); assert c.put("/api/admin/safety", json={"url": "http://x.test"}, headers={"Authorization": "Bearer " + t}).status_code == 403
    assert c.get("/api/safety/notices", headers={"Authorization": "Bearer " + t}).json()[0]["id"] == 1
    assert c.post("/api/safety/report", json={"notice_id": 1, "consent": True}, headers={"Authorization": "Bearer " + t}).json()["ref"] == "ARC-0001"
    assert "ben" in c.get("/api/bootstrap", headers={"Authorization": "Bearer " + t}).json()["blocks"]          # reporting also blocks the sender here
