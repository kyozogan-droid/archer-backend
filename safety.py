"""Pre-delivery safety hook (the 'integration contract'). Mazungumzo stays provider-neutral: an admin enters a safety service URL and a SERVER key under
Settings -> Safety. Before a direct message is delivered the server asks the service for a decision (deliver / warn / block). If the service is
unreachable the message is delivered (fail open). The service decides; the platform only enforces and displays."""
import base64, os
import httpx
from fastapi import HTTPException
TRANSPORT = None          # tests inject an ASGI transport here
_q = None
def init(q): global _q; _q = q
def conf():
    r = {x["k"]: x["v"] for x in _q("SELECT k,v FROM settings WHERE k LIKE 'safety_%'")}
    return {"url": r.get("safety_url", ""), "key": r.get("safety_key", ""), "enabled": r.get("safety_enabled") == "1"}
def enabled(): c = conf(); return bool(c["enabled"] and c["url"] and c["key"])
async def call(method, path, **kw):
    c = conf()
    if not (c["enabled"] and c["url"] and c["key"]): raise HTTPException(503, "The safety service is not connected")
    try:
        async with httpx.AsyncClient(base_url=c["url"].rstrip("/"), transport=TRANSPORT, timeout=15) as h:
            r = await h.request(method, path, headers={"X-Archer-Key": c["key"]}, **kw)
    except httpx.HTTPError: raise HTTPException(502, "The safety service is unreachable")
    if r.status_code >= 400:
        try: d = r.json().get("detail")
        except Exception: d = None
        raise HTTPException(r.status_code, d if isinstance(d, str) else "Safety service error")
    return r.json()
def b64(path, limit=4_000_000):
    try:
        if os.path.getsize(path) > limit: return None
        return base64.b64encode(open(path, "rb").read()).decode()
    except OSError: return None
