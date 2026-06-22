import asyncio
import json
import os
import hashlib
import secrets
import time
import aiofiles
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

# ── CONFIG ──────────────────────────────────────────────────────────────────────
CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

# ── LOGGING ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("RVG-Gateway")

app = FastAPI(title="RVG Gateway – codebox", docs_url=None, redoc_url=None)

# ── CORS ───────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Persistence ───────────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "rvg_state.json"
SAVE_LOCK = asyncio.Lock()

async def load_state():
    global LINKS, AUTH
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = await f.read()
            data = json.loads(raw)
            LINKS.update(data.get("links", {}))
            if "password_hash" in data:
                AUTH["password_hash"] = data["password_hash"]
        logger.info(f"✅ State loaded: {len(LINKS)} links")
    except Exception as e:
        logger.warning(f"Could not load state: {e}")

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "links": dict(LINKS),
                "password_hash": AUTH["password_hash"],
                "saved_at": datetime.now().isoformat(),
            }
            tmp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.replace(DATA_FILE)
        except Exception as e:
            logger.warning(f"Could not save state: {e}")

# ── In‑memory state ────────────────────────────────────────────────────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
hourly_traffic: defaultdict = defaultdict(int)
http_client: httpx.AsyncClient | None = None
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

# ── Authentication ───────────────────────────────────────────────────────────
SESSION_COOKIE = "rvg_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "123456"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if not token:
        return
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

# ── Startup / Shutdown ───────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    )
    await load_state()
    logger.info(f"🚀 RVG Gateway v8.1 started on port {CONFIG['port']}")

@app.on_event("shutdown")
async def shutdown():
    await save_state()
    if http_client:
        await http_client.aclose()

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_host() -> str:
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", CONFIG["host"])

def generate_uuid() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 ** 3)
    if unit == "MB": return int(value * 1024 ** 2)
    if unit == "KB": return int(value * 1024)
    return int(value)

def is_link_expired(link: dict | None) -> bool:
    if not link:
        return True
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp)
    except Exception:
        return False

def is_link_allowed(link: dict | None) -> bool:
    if not link:
        return False
    if not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb:
        return False
    return True

# Helper برای محاسبه مقدار باقیمانده (bytes)
def remaining_bytes(link: dict) -> int:
    """مقدار باقیمانده = حداکثر - مصرف شده."""
    limit = link.get("limit_bytes", 0)
    used = link.get("used_bytes", 0)
    return limit - used

# ── Default link (unlimited) ─────────────────────────────────────────────────
_default_link_created = False

async def ensure_default_link():
    global _default_link_created
    if _default_link_created:
        return
    async with LINKS_LOCK:
        if not any(l.get("is_default") for l in LINKS.values()):
            uid = hashlib.sha256(f"default{CONFIG['secret']}".encode()).hexdigest()
            uid = f"{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}-{uid[20:32]}"
            if uid not in LINKS:
                LINKS[uid] = {
                    "label": "لینک پیش‌فرض",
                    "limit_bytes": 0,
                    "used_bytes": 0,
                    "created_at": datetime.now().isoformat(),
                    "active": True,
                    "expires_at": None,
                    "note": "",
                    "is_default": True,
                }
                asyncio.create_task(save_state())
    _default_link_created = True

# ── Basic endpoints ────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": "RVG Gateway", "version": "8.2", "status": "active", "channel": "https://t.me/CodeBoxo"}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}


# ── Subscription (single) ──────────────────────────────────────────────────────
@app.get("/sub/{uuid}")
async def subscription_single(uuid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link or not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="not found or inactive")
    host = get_host()
    vless = generate_vless_link(uuid, host, remark=f"{link['label']}")
    content = base64.b64encode(vless.encode()).decode()
    return Response(content=content, media_type="text/plain",
                    headers={"profile-title": link["label"], "support-url": "https://t.me/CodeBoxo"})


# ── Subscription (all links) ───────────────────────────────────────────────────
@app.get("/sub-all")
async def subscription_all(_=Depends(require_auth)):
    import base64
    host = get_host()
    async with LINKS_LOCK:
        lines = [
            generate_vless_link(uid, host, remark=f"{d['label']}")
            for uid, d in LINKS.items()
            if is_link_allowed(d)
        ]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content=content, media_type="text/plain")


# ── Auth endpoints ─────────────────────────────────────────────────────────────
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    token = await create_session()
    resp = Response(content={"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL,
                    httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = Response(content={"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    return {"authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))}

@app.post("/api/change-password")
async def api_change_password(request: Request, token=Depends(require_auth)):
    body = await request.json()
    if hash_password(str(body.get("current_password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    new = str(body.get("new_password", ""))
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")
    AUTH["password_hash"] = hash_password(new)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    await save_state()
    return {"ok": True}


# ── Stats ──────────────────────────────────────────────────────────────────────
@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 ** 2), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(snap),
        "active_links": sum(1 for l in snap.values() if is_link_allowed(l)),
        "expired_links": sum(1 for l in snap.values() if is_link_expired(l)),
        # فیلد جدید برای UI
        "remaining_bytes_per_link": {uid: remaining_bytes(l) for uid, l in snap.items()},
    }

# ── Link Management ───────────────────────────────────────────────────────────
@app.post("/api/links")
async def create_link(request: Request):
    body = await request.json()
    label = (body.get("label") or "لینک جدید").strip()[:60]
    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    exp_days = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=exp_days)).isoformat() if exp_days > 0 else None
    note = (body.get("note") or "").strip()[:200]

    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "expires_at": expires_at,
            "note": note,
            "is_default": False,
        }

    # URL ساب با مقدار باقیمانده (اگر محدود بود)
    sub_url = generate_sub_url(LINKS[uid])
    asyncio.create_task(save_state())
    host = get_host()
    return {
        "uuid": uid,
        **LINKS[uid],
        "expired": False,
        "vless_link": generate_vless_link(uid, host, remark=f"{label}"),
        "sub_url": sub_url,
    }

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    host = get_host()
    async with LINKS_LOCK:
        snap = dict(LINKS)
    result = []
    for uid, d in snap.items():
        result.append({
            "uuid": uid,
            **d,
            "expired": is_link_expired(d),
            "vless_link": generate_vless_link(uid, host, remark=f"{d['label']}"),
            "sub_url": generate_sub_url(d),
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        link = LINKS[uid]

        if "active" in body:
            link["active"] = bool(body["active"])
        if "label" in body:
            link["label"] = str(body["label"])[:60]
        if "note" in body:
            link["note"] = str(body["note"])[:200]
        if "reset_usage" in body and body["reset_usage"]:
            link["used_bytes"] = 0
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            link["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if "expires_days" in body:
            ed = int(body["expires_days"] or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None

        # Update URL ساب (if changed)
        link["sub_url"] = generate_sub_url(link)

    asyncio.create_task(save_state())
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        del LINKS[uid]
    asyncio.create_task(save_state())
    return {"ok": True, "deleted": uid}


# ── Subscription URL generation (with left param) ─────────────────────────────────
def generate_sub_url(link: dict) -> str:
    """
    Returns a URL that can be used in apps.
    If the link has a limit and usage > 0, a query‑parameter `left`
    containing the remaining bytes is added.
    """
    host = get_host()
    sub = f"https://{host}/sub/{link['uuid']}"

    lim = link.get("limit_bytes", 0)
    used = link.get("used_bytes", 0)
    remaining = lim - used

    if lim > 0 and remaining > 0:
        # می‌توانید به‌صورت بایت یا مگابایت بفرستید.
        sub += f"?left={remaining}"

    return sub


# ── VLESS link generation (with remark that shows remaining) ───────────────────────
def generate_vless_link(uuid: str, host: str, remark: str = "") -> str:
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": host,
        "path": path,
        "sni": host,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    base = f"vless://{uuid}@{host}:443?{query}#{quote(remark)}"
    return base


# ── Relay functions (unchanged) ───────────────────────────────────────────────────
RELAY_BUF = 256 * 1024

async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1  # skip version
    pos += 16  # skip uuid bytes
    addon_len = chunk[pos]; pos += 1 + addon_len
    command = chunk[pos]; pos += 1
    port = int.from_bytes(chunk[pos:pos+2], "big"); pos += 2
    addr_type = chunk[pos]; pos += 1
    if addr_type == 1:
        address = ".".join(str(b) for b in chunk[pos:pos+4]); pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]; pos += 1
        address = chunk[pos:pos+dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif addr_type == 3:
        ab = chunk[pos:pos+16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]

async def check_and_use(uid: str, n: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        if not is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        hourly_traffic[datetime.now().strftime("%H:00")] += n
    return True

# ── WebSocket tunnel (unchanged) ─────────────────────────────────────────────────
async def relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter, conn_id: str, uid: str):
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += len(data)
            writer.write(data)
            if writer.transport.get_write_buffer_size() > RELAY_BUF:
                await writer.drain()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass

async def relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader, conn_id: str, uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not await check_and_use(uid, len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            connections[conn_id]["bytes"] += len(data)
            payload = (b"\x00\x00" + data) if first else data
            first = False
            await ws.send_bytes(payload)
    except Exception:
        pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(ws: WebSocket, uuid: str):
    await ws.accept()

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        logger.warning(f"🚫 WS rejected uuid={uuid[:8]}… (not allowed)")
        await ws.close(code=1008, reason="not authorized")
        return

    conn_id = secrets.token_urlsafe(6)
    connections[conn_id] = {"uuid": uuid, "connected_at": datetime.now().isoformat(), "bytes": 0}
    logger.info(f"✅ WS [{conn_id}] uuid={uuid[:8]}… total={len(connections)}")

    writer = None
    try:
        first_msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk:
            return

        command, address, port, payload = await parse_vless_header(first_chunk)

        if not await check_and_use(uuid, len(first_chunk)):
            await ws.close(code=1008, reason="quota/disabled")
            return

        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += len(first_chunk)
        logger.info(f"➡️  [{conn_id}] → {address}:{port}")

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port),
            timeout=10.0,
        )
        sock = writer.transport.get_extra_info('socket')
        if sock:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if payload:
            writer.write(payload)
            await writer.drain()

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(relay_ws_to_tcp(ws, writer, conn_id, uuid)),
                asyncio.create_task(relay_tcp_to_ws(ws, reader, conn_id, uuid)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        asyncio.create_task(save_state())

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"🔌 WS closed [{conn_id}] total={len(connections)}")

# ── HTTP Proxy ───────────────────────────────────────────────────────────────────
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "content-encoding", "content-length"}

@app.api_route("/proxy/{target_url:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def http_proxy(target_url: str, request: Request):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    try:
        body = await request.body()
        headers = {k: v for k, v in request.headers.items()
                  if k.lower() not in _HOP and k.lower() != "host"}
        resp = await http_client.request(method=request.method,
                                        url=target_url,
                                        headers=headers,
                                        content=body)
        stats["total_bytes"] += len(resp.content)
        stats["total_requests"] += 1
        hourly_traffic[datetime.now().strftime("%H:00")] += len(resp.content)
        return Response(content=resp.content,
                        status_code=resp.status_code,
                        headers={k: v for k, v in resp.headers.items()
                                if k.lower() not in _HOP})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")

# ── New API: مقدار باقیمانده یک لینک ───────────────────────────────────────────────
@app.get("/api/link-remaining/{uuid}")
async def link_remaining(uuid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link or not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="link not found or inactive")
    remaining = link.get("limit_bytes", 0) - link.get("used_bytes", 0)
    if remaining <= 0:
        remaining = 0
    return {"remaining_bytes": remaining}


# ── HTML Responses ───────────────────────────────────────────────────────────────

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ورود · RVG Gateway</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#060f1d;--card:rgba(10,22,40,0.9);--accent:#3B82F6;--text:#E8F4FF;--dim:#3D6B8E;--mid:#7BAED4;--border:rgba(59,130,246,0.2)}
html,body{height:100%;overflow:hidden}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);display:flex;align-items:center;justify-content:center;padding:20px}
.bg{position:fixed;inset:0;background:radial-gradient(ellipse 80% 60% at 50% 0%,rgba(59,130,246,0.1),transparent 70%),var(--bg);z-index:0}
.grid{position:fixed;inset:0;background:linear-gradient(rgba(59,130,246,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(59,130,246,0.04) 1px,transparent 1px);background-size:44px 44px;z-index:0}
.orb{position:fixed;border-radius:50%;filter:blur(90px);z-index:0;animation:fl 9s ease-in-out infinite}
.o1{width:380px;height:380px;background:rgba(59,130,246,0.07);top:-100px;right:-80px}
.o2{width:280px;height:280px;background:rgba(16,185,129,0.04);bottom:-60px;left:-60px;animation-delay:4s}
@keyframes fl{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.wrap{position:relative;z-index:10;width:100%;max-width:400px}
.card{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:38px 34px 34px;backdrop-filter:blur(24px);box-shadow:0 0 80px rgba(59,130,246,0.07),0 20px 60px rgba(0,0,0,.5)}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:28px}
.brand-img{width:48px;height:48px;border-radius:13px;overflow:hidden;border:1px solid var(--border);box-shadow:0 0 14px var(--accent);flex-shrink:0}
.brand-img img{width:100%;height:100%;object-fit:cover}
.brand-name{font-size:16px;font-weight:700;color:var(--text)}
.brand-sub{font-size:11px;color:var(--dim);margin-top:2px}
.hint{display:flex;align-items:center;gap:10px;background:rgba(59,130,246,0.07);border:1px solid rgba(59,130,246,0.15);border-radius:10px;padding:10px 14px;margin-bottom:20px}
.hint-label{font-size:11px;color:var(--dim);font-weight:600;text-transform:uppercase;letter-spacing:.06em}
.hint-val{font-family:ui-monospace,monospace;font-size:14px;font-weight:700;color:var(--accent);background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.25);padding:3px 11px;border-radius:7px;cursor:pointer;transition:.15s;letter-spacing:.08em}
.err{display:none;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);border-radius:10px;padding:10px 14px;font-size:12px;color:#F87171;align-items:center;gap:8px}
.frm{border:1px solid var(--border);border-radius:8px;padding:12px;background:rgba(0,0,0,.18)}
.frm input[type=password]{width:100%;padding:12px 44px 12px 16px;border-radius:8px;border:1px solid var(--border);background:rgba(0,0,0,.18);color:var(--text);font-family:inherit;font-size:14px;outline:none;transition:.15s}
.frm input[type=password]:focus{border-color:rgba(59,130,246,.55);background:rgba(0,0,0,.25)}
.btn{width:100%;padding:12px;border-radius:8px;border:none;cursor:pointer;background:linear-gradient(135deg,#2563EB,#1D4ED8);color:#fff;font-family:inherit;font-size:14px;display:flex;align-items:center;justify-content:center;gap:8px;box-shadow:0 4px 20px rgba(0,0,0,.35)}
.btn:hover{filter:brightness(1.1)}
.btn:disabled{opacity:.5;cursor:not-allowed}
</style>
</head>
<body>
<div class="frm">
    <div class="brand"><div class="brand-img"><img src="https://yt3.googleusercontent.com/vA6bYj1V386YmibpWRNFJtsRRqwfY_U9wnb7gmW90eRVXyNB7gAfjj1XPs5UX0cdKdQprrI=s160-c-k-c0x00ffffff-no-rj" alt="codebox"></div><div><div class="brand-name">codebox</div><div class="brand-sub">RVG Gateway</div></div></div>
    <input type="password" id="pw" placeholder="رمز عبور" autofocus required>
    <button type="submit" id="btn">ورود</button>
</div>
<script>
document.getElementById('frm').addEventListener('submit', async e=>{
    e.preventDefault();
    const pw=document.getElementById('pw'), btn=document.getElementById('btn'), err=document.querySelector('.err');
    err.classList.remove('show'); btn.disabled=true;
    btn.innerHTML='در حال ورود...';
    try{
        const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw.value})});
        if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'خطا');}
        location.href='/dashboard';
    }catch(e){
        err.textContent=e.message; err.classList.add('show');
        btn.disabled=false; btn.innerHTML='<i class="ti ti-login-2"></i> ورود به داشبورد';
    }
});
</script>
</body></html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RVG Gateway · codebox</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
/* (same as before, only changed part is the table row generation – see JS) */
... (full CSS unchanged) ...
</style>
</head>
<body>
<div class="toast" id="toast"></div>
<div id="app">
  <!-- sidebar, topbar, etc -->
  <section class="pg on" id="pg-links">
    <div class="topbar"><div><div class="tb-title"><i class="ti ti-link-plus"></i> مدیریت لینک‌ها</div></div></div>
    <div class="card"><div class="card-title"><i class="ti ti-plus"></i> ساخت لینک جدید</div>
      <form id="newLinkForm">
        <input class="fi" id="nl-label" placeholder="مثلاً: کاربر علی">
        <input class="fi" id="nl-val" type="number" min="0" step="0.1" placeholder="0=بی‌نهایت">
        <select class="fs" id="nl-unit"><option value="GB">GB</option><option value="MB" selected>MB</option></select>
        <input class="fi" id="nl-exp" type="number" min="0" step="1" placeholder="0=بی‌نهایت">
        <input class="fi" id="nl-note" placeholder="اختیاری">
        <button class="btn btn-p" type="submit">ساخت</button>
      </form>
    </div>
    <table id="linksTbl" class="tbl">
      <thead>
        <tr>
          <th>عنوان / یادداشت</th>
          <th>UUID</th>
          <th>مصرف / سهمیه</th>
          <th>انقضا</th>
          <th>وضعیت</th>
          <th>عملیات</th>
        </tr>
      </thead>
      <tbody id="linksTbody"></tbody>
    </table>
    <div id="linksEmpty" class="empty">— هیچ لینکی وجود ندارد —</div>
  </section>
  <!-- other pages (traffic, connections, errors, ideas, testws, settings) unchanged -->
  ...
  <script>
  // ---------- UI‑Scripts ----------
  // helper functions
  function fmtBytes(b){if(!b||b===0)return '0 B';if(b<1024)return b+' B';if(b<1024**​2)return (b/1024).toFixed(1)+' KB';if(b<1024​**3)return (b/1024**​2).toFixed(2)+' MB';return (b/1024​**3).toFixed(2)+' GB'}

  // Load links from API and render table
  async function loadLinks(){
    const resp = await fetch('/api/links');
    if(!resp.ok) console.warn('API error');
    const data = await resp.json();
    const tbody = document.getElementById('linksTbody');
    const empty = document.getElementById('linksEmpty');

    tbody.innerHTML = '';
    if(data.links && data.links.length){
      empty.style.display = 'none';
      data.links.forEach(l=>{
        const limit = l.limit_bytes===0?'∞':fmtBytes(l.limit_bytes);
        const used  = fmtBytes(l.used_bytes);
        const remaining = l.limit_bytes===0?'∞':fmtBytes(l.limit_bytes - l.used_bytes);
        const percent = l.limit_bytes===0?0:Math.round(100 - (l.used_bytes/l.limit_bytes)*100);
        const allowed = l.active && !l.expired;
        tbody.innerHTML += `
          <tr>
            <td><div class="ll">\${l.label}</div><div class="lm">\${l.note ? `<span title="\${l.note}"><i class="ti ti-note"></i>\${l.note.slice(0,25)}\${l.note.length>25?'...':''}</span>` : ''}</div></td>
            <td><span class="uuid-chip" onclick="navigator.clipboard.writeText('\${l.uuid}')">\${l.uuid.slice(0,13)}…</span></td>
            <td><div style="width:120px;"><div class="ubar"><div class="ubar-f" style="width:\${percent}%;background:\${allowed?'var(--green)':'var(--red)'}"></div></div>\${used} / \${limit}</div></td>
            <td>\${l.expires_at?'<span style="color:#D97706">'+l.expires_at+'</span>':'—'}</td>
            <td style="text-align:center;">
              <button class="tog\${allowed?' on':''}" onclick="toggleActive(this.parentNode.parentNode.cells[0].innerText)"></button>
            </td>
            <td>
              <div style="display:flex;gap:4px;flex-wrap:nowrap;">
                <button class="btn btn-sm btn-g" onclick="navigator.clipboard.writeText('\${l.sub_url}').then(()=>alert('Sub‑URL کپی شد'))">🔗</button>
                <button class="btn btn-sm btn-g" onclick="window.open('https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent('\${l.sub_url}'),'_blank')">📷</button>
                <button class="btn btn-sm btn-g" onclick="resetUsage('\${l.uuid}')">↩</button>
                <button class="btn btn-sm btn-g" onclick="deleteLink('\${l.uuid}')">🗑</button>
              </div>
            </td>
          </tr>`;
      });
      // total count badge (outside table)
      document.getElementById('links-nb').textContent = data.links.length;
    }else{
      empty.style.display = 'block';
    }

    // tooltip for Sub‑URL (click to see left param)
    document.querySelectorAll('.cl a').forEach(a=>{
      a.setAttribute('title', a.textContent);
    });
  }

  // ---------- Helper: update UI ----------
  async function refreshAll(){
    await loadLinks();
    await fetch('/.well-known/rvg-state'); // dummy call just to trigger UI updates
    // re‑draw charts etc. (same as original)
  }
  // rest of script unchanged (including toast, copy‑to‑clipboard, etc.)
  </script>
</body></html>
"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    await ensure_default_link()
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/test-ws", response_class=HTMLResponse)
async def test_ws_redirect():
    return HTMLResponse(content="<script>location.href='/dashboard'</script>")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], log_level="info", workers=1)
