import io, os, tempfile
os.environ["MZ_DB"] = os.path.join(tempfile.mkdtemp(), "t.db"); os.environ["MZ_DIST"] = tempfile.mkdtemp()
open(os.path.join(os.environ["MZ_DIST"], "index.html"), "w").write("<html><head><title>x</title></head><body></body></html>")
from fastapi.testclient import TestClient
from app import app
c = TestClient(app)
def reg(n): return {"Authorization": "Bearer " + c.post("/api/register", json={"name": n, "password": "secret123"}).json()["token"]}
def nxt(ws, t):
    while True:
        m = ws.receive_json()
        if m["type"] == t: return m

def test_auth_and_first_user_is_admin():
    ha = reg("ann"); hb = reg("bob")
    assert c.post("/api/login", json={"name": "ann", "password": "wrongpass"}).status_code == 401
    assert c.post("/api/register", json={"name": "ann", "password": "secret123"}).status_code == 409
    assert c.get("/api/me", headers=ha).json()["admin"] is True and c.get("/api/me", headers=hb).json()["admin"] is False

def test_upload_media_only():
    h = reg("up"); assert c.post("/api/upload", files={"file": ("a.txt", io.BytesIO(b"hi"), "text/plain")}, headers=h).status_code == 400
    assert c.post("/api/upload", files={"file": ("a.png", io.BytesIO(b"\x89PNG"), "image/png")}, headers=h).json()["kind"] == "image"

def test_feed_likes_comments_and_block():
    ha, hb = c.post("/api/login", json={"name": "ann", "password": "secret123"}).json(), reg("fay")
    ha = {"Authorization": "Bearer " + ha["token"]}
    assert c.post("/api/posts", json={"text": "  "}, headers=hb).status_code == 400
    c.post("/api/posts", json={"text": "hello world"}, headers=hb); pid = c.get("/api/feed", headers=ha).json()[0]["id"]
    c.post(f"/api/posts/{pid}/like", headers=ha); assert c.get("/api/feed", headers=ha).json()[0]["likes"] == 1 and c.get("/api/feed", headers=ha).json()[0]["liked"]
    c.post(f"/api/posts/{pid}/like", headers=ha); assert c.get("/api/feed", headers=ha).json()[0]["likes"] == 0
    c.post(f"/api/posts/{pid}/comments", json={"text": "nice"}, headers=ha); assert c.get(f"/api/posts/{pid}/comments", headers=hb).json()[0]["author"] == "ann"
    c.post("/api/block", json={"name": "fay"}, headers=ha); assert c.get("/api/feed", headers=ha).json() == []

def test_groups_status_and_chat_privacy():
    ha, hb, hc = reg("amy"), reg("ben"), reg("cat")
    assert c.post("/api/groups", json={"name": "g", "members": ["ben"]}, headers=ha).status_code == 400
    gid = c.post("/api/groups", json={"name": "Friends", "members": ["ben", "cat"]}, headers=ha).json()["id"]
    assert any(x["id"] == gid for x in c.get("/api/bootstrap", headers=hc).json()["convs"])
    c.post("/api/status", json={"text": "hi all"}, headers=ha); sid = c.get("/api/statuses", headers=hb).json()[0]["id"]; c.post(f"/api/status/{sid}/view", headers=hb)
    assert c.get("/api/statuses", headers=ha).json()[0]["views"] == 1
    with c.websocket_connect("/ws?token=" + hb["Authorization"].split()[1]) as wb:
        nxt(wb, "presence"); wb.send_json({"type": "msg", "conv": "dm:amy|ben", "text": "hi amy"}); assert nxt(wb, "msg")["text"] == "hi amy"
    assert [m["text"] for m in c.get("/api/conv/dm:amy|ben/messages", headers=ha).json()] == ["hi amy"]
    assert c.get("/api/conv/dm:amy|ben/messages", headers=hc).status_code == 403

def test_custom_code_is_admin_only_and_injected_without_source_changes():
    ha = {"Authorization": "Bearer " + c.post("/api/login", json={"name": "ann", "password": "secret123"}).json()["token"]}; hb = reg("zed")
    assert "<script" not in c.get("/").text
    assert c.put("/api/admin/settings", json={"head_code": "<script src='x'></script>"}, headers=hb).status_code == 403
    assert c.put("/api/admin/settings", json={"head_code": "<script src='https://x.test/s.js' data-k='1'></script>"}, headers=ha).status_code == 200
    assert "https://x.test/s.js" in c.get("/").text.split("</head>")[0]
    assert c.get("/api/admin/settings", headers=hb).status_code == 403
