"""Mazungumzo: a social platform (feed, chats, groups, status, photos/video, replies, read ticks, typing/online, block).
React frontend + FastAPI/SQLite backend. It contains NO ARCHER code and no ARCHER settings. Like WordPress or Wix, the admin can add
third-party scripts under Settings -> Custom code, which is injected into the page at serve time (no source editing).
Not hardened for production: no rate limits, uploads are public by URL. Run: uvicorn app:app --port 9000"""
import os, re, json, time, uuid, secrets, hashlib, hmac, sqlite3, threading, mimetypes
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException, Header, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import safety

BASE = os.path.dirname(os.path.abspath(__file__)); UP = os.path.join(BASE, "uploads"); os.makedirs(UP, exist_ok=True)
DIST = os.path.abspath(os.getenv("MZ_DIST", os.path.join(BASE, "..", "frontend", "dist")))
con = sqlite3.connect(os.getenv("MZ_DB", os.path.join(BASE, "mazungumzo.db")), check_same_thread=False); con.row_factory = sqlite3.Row; _l = threading.Lock()
con.executescript("""
CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY, salt BLOB, pw BLOB, admin INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, name TEXT);
CREATE TABLE IF NOT EXISTS groups(id TEXT PRIMARY KEY, name TEXT, owner TEXT);
CREATE TABLE IF NOT EXISTS members(gid TEXT, name TEXT, PRIMARY KEY(gid, name));
CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY, conv TEXT, sender TEXT, text TEXT, mkind TEXT, murl TEXT, reply TEXT, ts REAL, st INT DEFAULT 0, flag TEXT, tr TEXT);
CREATE TABLE IF NOT EXISTS seen(user TEXT, conv TEXT, ts REAL, PRIMARY KEY(user, conv));
CREATE TABLE IF NOT EXISTS statuses(id TEXT PRIMARY KEY, owner TEXT, text TEXT, mkind TEXT, murl TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS sviews(sid TEXT, viewer TEXT, PRIMARY KEY(sid, viewer));
CREATE TABLE IF NOT EXISTS posts(id TEXT PRIMARY KEY, author TEXT, text TEXT, mkind TEXT, murl TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS likes(pid TEXT, user TEXT, PRIMARY KEY(pid, user));
CREATE TABLE IF NOT EXISTS comments(id TEXT PRIMARY KEY, pid TEXT, author TEXT, text TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS blocks(blocker TEXT, blocked TEXT, PRIMARY KEY(blocker, blocked));
""")
def q(sql, *a):
    with _l: c = con.execute(sql, a); con.commit(); return c.fetchall()
for _col in ("flag", "tr"):                      # upgrade databases created before voice notes / trusted labels
    try: q(f"ALTER TABLE messages ADD COLUMN {_col} TEXT")
    except sqlite3.OperationalError: pass
safety.init(q)
app = FastAPI(title="Mazungumzo"); conns = {}
# Frontend and backend are deployed separately, so the browser needs CORS permission.
# MZ_CORS_ORIGINS = comma-separated frontend addresses, e.g. "https://mazungumzo.vercel.app". Default "*" (fine for testing: auth is a Bearer header, not cookies).
ORIGINS = [o.strip().rstrip("/") for o in os.getenv("MZ_CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".webm", ".mov", ".ogg", ".m4a", ".mp3", ".wav"}
def hp(pw, salt): return hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)

class Cred(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{2,20}$"); password: str = Field(min_length=6, max_length=100)
@app.post("/api/register")
def register(c: Cred):
    if q("SELECT 1 FROM users WHERE name=?", c.name): raise HTTPException(409, "That name is taken")
    s = secrets.token_bytes(16); first = not q("SELECT 1 FROM users LIMIT 1")   # the first account is the platform admin
    q("INSERT INTO users(name,salt,pw,admin) VALUES(?,?,?,?)", c.name, s, hp(c.password, s), int(first)); return login(c)
@app.post("/api/login")
def login(c: Cred):
    r = q("SELECT * FROM users WHERE name=?", c.name)
    if not r or not hmac.compare_digest(r[0]["pw"], hp(c.password, r[0]["salt"])): raise HTTPException(401, "Wrong name or password")
    t = secrets.token_urlsafe(24); q("INSERT INTO sessions VALUES(?,?)", t, c.name); return {"token": t, "name": c.name}
def user(authorization: str = Header(None)):
    r = q("SELECT name FROM sessions WHERE token=?", (authorization or "").removeprefix("Bearer "))
    if not r: raise HTTPException(401, "Sign in first")
    return r[0]["name"]

def admin_user(me=Depends(user)):
    if not q("SELECT admin FROM users WHERE name=?", me)[0]["admin"]: raise HTTPException(403, "Admins only")
    return me
@app.get("/api/me")
def whoami(me=Depends(user)): return {"name": me, "admin": bool(q("SELECT admin FROM users WHERE name=?", me)[0]["admin"]), "safety": safety.enabled()}

def parts(conv):
    if conv.startswith("dm:"): return [p for p in conv[3:].split("|") if q("SELECT 1 FROM users WHERE name=?", p)] if conv.count("|") == 1 else []
    if conv.startswith("g:"): return [r["name"] for r in q("SELECT name FROM members WHERE gid=?", conv[2:])]
    return []
def blocked(n): return {r["blocked"] for r in q("SELECT blocked FROM blocks WHERE blocker=?", n)}
def media(k, u): return {"kind": k, "url": u} if u else None
def mout(r):
    rep = None
    if r["reply"]:
        x = q("SELECT sender,text FROM messages WHERE id=?", r["reply"]); rep = {"from": x[0]["sender"], "text": x[0]["text"]} if x else None
    return {"id": r["id"], "conv": r["conv"], "from": r["sender"], "text": r["text"], "media": media(r["mkind"], r["murl"]), "reply": rep, "ts": r["ts"], "st": r["st"], "flag": r["flag"], "transcript": r["tr"]}
def clean_media(m):
    if isinstance(m, dict) and m.get("kind") in ("image", "video", "voice") and re.fullmatch(r"/uploads/[0-9a-f]{32}\.\w{2,4}", str(m.get("url", ""))): return m["kind"], m["url"]
    return None, None
def my_convs(n):
    cs = {r["conv"] for r in q("SELECT DISTINCT conv FROM messages WHERE conv LIKE 'dm:%'") if n in r["conv"][3:].split("|")}
    return cs | {"g:" + r["gid"] for r in q("SELECT gid FROM members WHERE name=?", n)}
async def push(names, payload):
    for n in set(names):
        s = conns.get(n)
        if s:
            try: await s.send_json(payload)
            except Exception: pass

@app.get("/api/bootstrap")
def bootstrap(me=Depends(user)):
    bl = blocked(me); out = []
    for c in my_convs(me):
        rows = [r for r in q("SELECT * FROM messages WHERE conv=? ORDER BY ts", c) if r["sender"] not in bl]
        sn = q("SELECT ts FROM seen WHERE user=? AND conv=?", me, c); t0 = sn[0]["ts"] if sn else 0
        g = q("SELECT name FROM groups WHERE id=?", c[2:]) if c.startswith("g:") else None
        out.append({"id": c, "title": g[0]["name"] if g else None, "members": parts(c), "last": mout(rows[-1]) if rows else None,
                    "unread": sum(1 for r in rows if r["ts"] > t0 and r["sender"] != me)})
    return {"me": me, "users": [r["name"] for r in q("SELECT name FROM users ORDER BY name")], "convs": out, "blocks": sorted(bl), "online": list(conns)}

@app.get("/api/conv/{conv}/messages")
def messages(conv: str, me=Depends(user)):
    if me not in parts(conv): raise HTTPException(403, "Not in this chat")
    bl = blocked(me); return [mout(r) for r in q("SELECT * FROM messages WHERE conv=? ORDER BY ts DESC LIMIT 100", conv)[::-1] if r["sender"] not in bl]

@app.post("/api/upload")
async def upload(file: UploadFile = File(...), me=Depends(user)):
    kind = (file.content_type or "").split("/")[0]
    if kind not in ("image", "video", "audio"): raise HTTPException(400, "Images, videos and voice notes only")
    data = await file.read()
    if len(data) > 25 * 1024 * 1024: raise HTTPException(413, "Max 25 MB")
    ext = os.path.splitext(file.filename or "")[1].lower(); ext = ext if ext in EXT else (".mp4" if kind == "video" else ".webm" if kind == "audio" else ".jpg")
    name = uuid.uuid4().hex + ext; open(os.path.join(UP, name), "wb").write(data)
    return {"url": "/uploads/" + name, "kind": "voice" if kind == "audio" else kind}

class Grp(BaseModel):
    name: str = Field(min_length=1, max_length=30); members: list[str]
@app.post("/api/groups")
async def mk_group(g: Grp, me=Depends(user)):
    ms = {m for m in g.members if q("SELECT 1 FROM users WHERE name=?", m)} | {me}
    if len(ms) < 3: raise HTTPException(400, "A group needs at least 3 people (you + 2 others)")
    gid = uuid.uuid4().hex[:8]; q("INSERT INTO groups VALUES(?,?,?)", gid, g.name, me)
    for m in ms: q("INSERT INTO members VALUES(?,?)", gid, m)
    await push(ms, {"type": "conv"}); return {"id": "g:" + gid}

class St(BaseModel):
    text: str = Field("", max_length=700); media: dict | None = None
@app.post("/api/status")
def post_status(s: St, me=Depends(user)):
    mk, mu = clean_media(s.media)
    if not (s.text.strip() or mu): raise HTTPException(400, "Empty status")
    q("INSERT INTO statuses VALUES(?,?,?,?,?,?)", uuid.uuid4().hex, me, s.text.strip(), mk, mu, time.time()); return {"ok": True}
@app.get("/api/statuses")        # last 24 hours, from people you have not blocked
def statuses(me=Depends(user)):
    bl = blocked(me); out = []
    for r in q("SELECT * FROM statuses WHERE ts>? ORDER BY ts", time.time() - 86400):
        if r["owner"] in bl: continue
        own = r["owner"] == me
        out.append({"id": r["id"], "owner": r["owner"], "text": r["text"], "media": media(r["mkind"], r["murl"]), "ts": r["ts"],
                    "seen": own or bool(q("SELECT 1 FROM sviews WHERE sid=? AND viewer=?", r["id"], me)),
                    "views": q("SELECT COUNT(*) c FROM sviews WHERE sid=?", r["id"])[0]["c"] if own else None})
    return out
@app.post("/api/status/{sid}/view")
def view(sid: str, me=Depends(user)): q("INSERT OR IGNORE INTO sviews VALUES(?,?)", sid, me); return {"ok": True}

class Nm(BaseModel): name: str
@app.post("/api/block")
def block(n: Nm, me=Depends(user)): q("INSERT OR IGNORE INTO blocks VALUES(?,?)", me, n.name); return {"ok": True}
@app.post("/api/unblock")
def unblock(n: Nm, me=Depends(user)): q("DELETE FROM blocks WHERE blocker=? AND blocked=?", me, n.name); return {"ok": True}

def _rm(url):
    try: os.remove(os.path.join(UP, os.path.basename(url)))
    except OSError: pass
async def screen(me, other, text, m, mk, mu, tr):
    """Ask the safety service for a decision. Any failure -> None -> the message is delivered (fail open)."""
    try:
        media = None
        if mu:
            path = os.path.join(UP, os.path.basename(mu)); b = safety.b64(path)
            media = {"kind": mk, "flagged": bool(m.get("flag")), "mime": mimetypes.guess_type(path)[0] or "", "content_b64": b, **({"transcript": tr} if tr else {}), **({"audio_b64": b} if mk == "voice" and not tr else {})}
        return await safety.call("POST", "/api/gateway/submit", json={"sender_id": me, "sender_name": me, "receiver_id": other, "receiver_name": other, "text": text, "media": media, "lang": "sw" if m.get("lang") == "sw" else "en", "acknowledged": bool(m.get("ack"))})
    except Exception: return None

@app.websocket("/ws")
async def ws(sock: WebSocket, token: str = ""):
    o = (sock.headers.get("origin") or "").rstrip("/")      # browsers do not apply CORS to WebSockets, so check the origin here
    if "*" not in ORIGINS and o and o not in ORIGINS: await sock.close(code=4403); return
    r = q("SELECT name FROM sessions WHERE token=?", token)
    if not r: await sock.close(code=4401); return
    me = r[0]["name"]; await sock.accept(); conns[me] = sock; await push(conns, {"type": "presence", "online": list(conns)})
    for c in my_convs(me):       # messages received while offline become "delivered"
        if c.startswith("dm:") and q("SELECT 1 FROM messages WHERE conv=? AND sender!=? AND st=0", c, me):
            q("UPDATE messages SET st=1 WHERE conv=? AND sender!=? AND st=0", c, me); await push(parts(c), {"type": "receipt", "conv": c, "st": 1})
    try:
        while True:
            m = await sock.receive_json(); t = m.get("type"); c = str(m.get("conv", ""))
            if me not in parts(c): continue
            others = [p for p in parts(c) if p != me]
            if t == "msg":
                text = str(m.get("text", ""))[:2000]; mk, mu = clean_media(m.get("media"))
                if not (text.strip() or mu): continue
                rid = m.get("reply") if m.get("reply") and q("SELECT 1 FROM messages WHERE id=? AND conv=?", m.get("reply"), c) else None
                flag = None; tr = str(m.get("transcript") or "")[:2000] or None
                if c.startswith("dm:") and others and safety.enabled() and others[0] not in blocked(me):
                    res = await screen(me, others[0], text, m, mk, mu, tr)
                    if res and res["decision"] == "block":
                        if mu: _rm(mu)
                        n = res.pop("notice"); await push([me], {"type": "blocked", "conv": c, **res}); await push([others[0]], {"type": "notice", "notice": n}); continue
                    if res and res["decision"] == "warn":
                        await push([me], {"type": "warn", "conv": c, "message": res["message"], "category": res["category"], "draft": m}); continue
                    if res and res["decision"] == "deliver_trusted": flag = f'{res["category"]}:{res.get("notice_id") or ""}'
                mid = uuid.uuid4().hex; st = 1 if c.startswith("dm:") and others[0] in conns else 0
                q("INSERT INTO messages(id,conv,sender,text,mkind,murl,reply,ts,st,flag,tr) VALUES(?,?,?,?,?,?,?,?,?,?,?)", mid, c, me, text, mk, mu, rid, time.time(), st, flag, tr)
                await push([me] + [p for p in others if me not in blocked(p)], {"type": "msg", **mout(q("SELECT * FROM messages WHERE id=?", mid)[0])})
            elif t == "read":
                q("INSERT INTO seen VALUES(?,?,?) ON CONFLICT(user,conv) DO UPDATE SET ts=excluded.ts", me, c, time.time())
                if c.startswith("dm:"): q("UPDATE messages SET st=2 WHERE conv=? AND sender!=? AND st<2", c, me); await push(parts(c), {"type": "receipt", "conv": c, "st": 2})
            elif t == "typing": await push(others, {"type": "typing", "conv": c, "user": me})
    except WebSocketDisconnect:
        conns.pop(me, None); await push(conns, {"type": "presence", "online": list(conns)})

class Post(BaseModel):
    text: str = Field("", max_length=3000); media: dict | None = None
class Cmt(BaseModel): text: str = Field(min_length=1, max_length=1000)
def pout(r, me):
    return {"id": r["id"], "author": r["author"], "text": r["text"], "media": media(r["mkind"], r["murl"]), "ts": r["ts"],
            "likes": q("SELECT COUNT(*) c FROM likes WHERE pid=?", r["id"])[0]["c"], "liked": bool(q("SELECT 1 FROM likes WHERE pid=? AND user=?", r["id"], me)),
            "comments": q("SELECT COUNT(*) c FROM comments WHERE pid=?", r["id"])[0]["c"]}
@app.get("/api/feed")
def feed(me=Depends(user)):
    bl = blocked(me); return [pout(r, me) for r in q("SELECT * FROM posts ORDER BY ts DESC LIMIT 50") if r["author"] not in bl]
@app.post("/api/posts")
def new_post(p: Post, me=Depends(user)):
    mk, mu = clean_media(p.media)
    if not (p.text.strip() or mu): raise HTTPException(400, "Write something or add a photo or video")
    q("INSERT INTO posts VALUES(?,?,?,?,?,?)", uuid.uuid4().hex, me, p.text.strip(), mk, mu, time.time()); return {"ok": True}
@app.post("/api/posts/{pid}/like")
def like(pid: str, me=Depends(user)):
    if q("SELECT 1 FROM likes WHERE pid=? AND user=?", pid, me): q("DELETE FROM likes WHERE pid=? AND user=?", pid, me)
    else: q("INSERT INTO likes VALUES(?,?)", pid, me)
    return {"ok": True}
@app.get("/api/posts/{pid}/comments")
def comments(pid: str, me=Depends(user)):
    bl = blocked(me); return [{"id": r["id"], "author": r["author"], "text": r["text"], "ts": r["ts"]} for r in q("SELECT * FROM comments WHERE pid=? ORDER BY ts", pid) if r["author"] not in bl]
@app.post("/api/posts/{pid}/comments")
def comment(pid: str, c: Cmt, me=Depends(user)):
    if not q("SELECT 1 FROM posts WHERE id=?", pid): raise HTTPException(404, "Post not found")
    q("INSERT INTO comments VALUES(?,?,?,?,?)", uuid.uuid4().hex, pid, me, c.text.strip(), time.time()); return {"ok": True}

class Head(BaseModel): head_code: str = Field("", max_length=5000)
@app.get("/api/admin/settings")
def get_settings(me=Depends(admin_user)):
    r = q("SELECT v FROM settings WHERE k='head_code'"); return {"head_code": r[0]["v"] if r else ""}
@app.put("/api/admin/settings")
def put_settings(h: Head, me=Depends(admin_user)):
    q("INSERT INTO settings VALUES('head_code',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", h.head_code.strip()); return {"ok": True}

@app.get("/api/public/head")      # the static frontend fetches the admin's custom code from here and adds it to <head>
def public_head():
    r = q("SELECT v FROM settings WHERE k='head_code'"); return {"head_code": r[0]["v"] if r else ""}
@app.get("/api/health")
def health(): return {"ok": True}
@app.get("/")
def index():
    if not os.path.isfile(os.path.join(DIST, "index.html")): return {"service": "Mazungumzo API", "docs": "/docs"}   # API-only deployment   # the page is served with the admin's custom head code injected (Settings -> Custom code)
    html = open(os.path.join(DIST, "index.html"), encoding="utf-8").read(); r = q("SELECT v FROM settings WHERE k='head_code'")
    return HTMLResponse(html.replace("</head>", (r[0]["v"] if r else "") + "\n</head>", 1), headers={"Cache-Control": "no-store"})
if os.path.isdir(os.path.join(DIST, "assets")): app.mount("/assets", StaticFiles(directory=os.path.join(DIST, "assets")), name="assets")
app.mount("/uploads", StaticFiles(directory=UP), name="uploads")

# ---- safety centre (proxied to the safety service with the server key, so the key never reaches the browser)
class Idn(BaseModel): notice_id: int | None = None; action: str = ""; note: str = Field("", max_length=1000); consent: bool = False; sender_id: str = ""; attempt_id: int | None = None; outcome: str = ""
@app.get("/api/safety/notices")
async def s_notices(me=Depends(user)): return await safety.call("GET", "/api/gateway/notices", params={"user_id": me})
@app.post("/api/safety/notices/{nid}/view")
async def s_view(nid: int, me=Depends(user)): return await safety.call("POST", f"/api/gateway/notices/{nid}/view", json={"user_id": me})
@app.post("/api/safety/notices/{nid}/action")
async def s_action(nid: int, b: Idn, me=Depends(user)): return await safety.call("POST", f"/api/gateway/notices/{nid}/action", json={"user_id": me, "action": b.action})
@app.get("/api/safety/trust")
async def s_trust(me=Depends(user)): return await safety.call("GET", "/api/gateway/trust", params={"user_id": me})
@app.post("/api/safety/trust/revoke")
async def s_revoke(b: Idn, me=Depends(user)): return await safety.call("POST", "/api/gateway/trust/revoke", json={"user_id": me, "sender_id": b.sender_id})
@app.post("/api/safety/report")
async def s_report(b: Idn, me=Depends(user)):
    r = await safety.call("POST", "/api/gateway/reports", json={"user_id": me, "notice_id": b.notice_id, "note": b.note, "consent": b.consent})
    n = [x for x in await safety.call("GET", "/api/gateway/notices", params={"user_id": me}) if x["id"] == b.notice_id]
    if n: q("INSERT OR IGNORE INTO blocks VALUES(?,?)", me, n[0]["sender_id"])        # a report also blocks the sender on this platform
    return r
@app.get("/api/safety/reports")
async def s_reports(me=Depends(user)): return await safety.call("GET", "/api/gateway/reports", params={"user_id": me})
@app.get("/api/safety/standing")
async def s_standing(me=Depends(user)): return await safety.call("GET", "/api/gateway/standing", params={"user_id": me})
@app.post("/api/safety/appeal")
async def s_appeal(b: Idn, me=Depends(user)): return await safety.call("POST", "/api/gateway/appeals", json={"user_id": me, "note": b.note})
@app.post("/api/safety/outcome")
async def s_outcome(b: Idn, me=Depends(user)): return await safety.call("POST", "/api/gateway/outcome", json={"attempt_id": b.attempt_id, "outcome": b.outcome})

class Saf(BaseModel): url: str = Field("", max_length=200); key: str = Field("", max_length=200); enabled: bool = False
@app.get("/api/admin/safety")
def get_safety(me=Depends(admin_user)): c = safety.conf(); return {"url": c["url"], "enabled": c["enabled"], "has_key": bool(c["key"])}
@app.put("/api/admin/safety")
def put_safety(b: Saf, me=Depends(admin_user)):
    if b.url and not re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:\d+)?/?", b.url.strip()): raise HTTPException(400, "Use an address like http://localhost:8000")
    for k, v in (("safety_url", b.url.strip()), ("safety_enabled", "1" if b.enabled else "0")) + ((("safety_key", b.key.strip()),) if b.key.strip() else ()):
        q("INSERT INTO settings VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, v)
    return get_safety(me)
@app.post("/api/admin/safety/test")
async def test_safety(me=Depends(admin_user)):
    c = safety.conf()
    try:
        async with safety.httpx.AsyncClient(base_url=c["url"].rstrip("/"), transport=safety.TRANSPORT, timeout=8) as h:
            ok = (await h.get("/api/health")).json().get("gateway") == 2
            auth = (await h.get("/api/gateway/trust", params={"user_id": "x"}, headers={"X-Archer-Key": c["key"]})).status_code == 200
        return {"reachable": True, "gateway": ok, "key_ok": auth}
    except Exception: return {"reachable": False, "gateway": False, "key_ok": False}
