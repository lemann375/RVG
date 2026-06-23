import asyncio
import json
import os
import hashlib
import secrets
import time
import base64
import aiofiles
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("RVG-Gateway")

app = FastAPI(title="RVG Gateway – Panel", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Persistence ──────────────────────────────────────────────────────────────
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

# ── In-memory state ──────────────────────────────────────────────────────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

# ── Auth ─────────────────────────────────────────────────────────────────────
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
        if exp is None:
            return False
        if exp < time.time():
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

# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(
        limits=limits, timeout=timeout, follow_redirects=True,
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
    return f"vless://{uuid}@{host}:443?{query}#{quote(remark)}"

def format_bytes(size: int, decimal_places: int = 1) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size/1024:.{decimal_places}f} KB"
    elif size < 1024**3:
        return f"{size/1024**2:.{decimal_places}f} MB"
    else:
        return f"{size/1024**3:.{decimal_places}f} GB"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 ** 3)
    if unit == "MB": return int(value * 1024 ** 2)
    if unit == "KB": return int(value * 1024)
    return int(value)

def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp)
    except Exception:
        return False

def is_link_allowed(link: dict | None) -> bool:
    if link is None:
        return False
    if not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb:
        return False
    return True

def make_profile_title(remark: str) -> str:
    """Encode a remark for use in HTTP header, supporting UTF-8."""
    try:
        remark.encode("latin-1")
        return remark
    except UnicodeEncodeError:
        b64 = base64.b64encode(remark.encode("utf-8")).decode("ascii")
        return f"=?UTF-8?B?{b64}?="

# ── Default link ──────────────────────────────────────────────────────────────
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

# ── Basic endpoints ───────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": "RVG Gateway", "version": "8.2", "status": "active", "channel": "https://t.me/CodeBoxo"}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ── Subscription ──────────────────────────────────────────────────────────────
NO_CACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

@app.get("/sub/{uuid}")
async def subscription_single(uuid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link or not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="not found or inactive")
    host = get_host()

    used_str = format_bytes(link["used_bytes"])
    limit_str = format_bytes(link["limit_bytes"]) if link["limit_bytes"] > 0 else "∞"
    remark = f"{link['label']} ({used_str}/{limit_str})"

    vless = generate_vless_link(uuid, host, remark=remark)
    content = base64.b64encode(vless.encode()).decode()
    headers = {
        **NO_CACHE_HEADERS,
        "profile-title": make_profile_title(remark),
        "support-url": "https://t.me/CodeBoxo"
    }
    return Response(content=content, media_type="text/plain", headers=headers)

@app.get("/sub-all")
async def subscription_all(_=Depends(require_auth)):
    host = get_host()
    async with LINKS_LOCK:
        lines = []
        for uid, d in LINKS.items():
            if not is_link_allowed(d):
                continue
            used_str = format_bytes(d["used_bytes"])
            limit_str = format_bytes(d["limit_bytes"]) if d["limit_bytes"] > 0 else "∞"
            remark = f"{d['label']} ({used_str}/{limit_str})"
            lines.append(generate_vless_link(uid, host, remark=remark))
    content = base64.b64encode("\n".join(lines).encode()).decode()
    headers = {
        **NO_CACHE_HEADERS,
        "profile-title": make_profile_title("RVG All Configs"),
        "support-url": "https://t.me/CodeBoxo"
    }
    return Response(content=content, media_type="text/plain", headers=headers)

# ── Auth endpoints ────────────────────────────────────────────────────────────
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
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
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL
    await save_state()
    return {"ok": True}

# ── Stats ─────────────────────────────────────────────────────────────────────
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
    }

# ── Connections list ─────────────────────────────────────────────────────────
@app.get("/api/connections")
async def get_connections(_=Depends(require_auth)):
    user_map = {}
    for conn_id, info in connections.items():
        uid = info["uuid"]
        if uid not in user_map:
            label = info.get("label")
            if label is None:
                async with LINKS_LOCK:
                    link = LINKS.get(uid)
                    label = link["label"] if link else "ناشناس"
            user_map[uid] = {
                "uuid": uid,
                "label": label,
                "active_connections": 0,
                "total_bytes": 0,
            }
        user_map[uid]["active_connections"] += 1
        user_map[uid]["total_bytes"] += info["bytes"]
    return {"users": list(user_map.values())}

# ── Link Management ───────────────────────────────────────────────────────────
@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
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
    asyncio.create_task(save_state())
    host = get_host()
    return {
        "uuid": uid,
        **LINKS[uid],
        "expired": False,
        "vless_link": generate_vless_link(uid, host, remark=label),
        "sub_url": f"https://{host}/sub/{uid}",
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
            "vless_link": generate_vless_link(uid, host, remark=d['label']),
            "sub_url": f"https://{host}/sub/{uid}",
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

# ══════════════════════════════════════════════════════════════════════════════
# VLESS Relay
# ══════════════════════════════════════════════════════════════════════════════

RELAY_BUF = 256 * 1024

async def parse_vless_header(chunk: bytes):
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1
    pos += 16
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
    connections[conn_id] = {
        "uuid": uuid,
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
        "label": link["label"] if link else "ناشناس",
    }
    logger.info(f"✅ WS [{conn_id}] uuid={uuid[:8]}… label={connections[conn_id]['label']} total={len(connections)}")
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
            timeout=10.0
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

# ── HTTP Proxy ────────────────────────────────────────────────────────────────
_HOP = {"connection","keep-alive","proxy-authenticate","proxy-authorization",
        "te","trailers","transfer-encoding","upgrade","content-encoding","content-length"}

@app.api_route("/proxy/{target_url:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def http_proxy(target_url: str, request: Request):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    try:
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP and k.lower() != "host"}
        resp = await http_client.request(method=request.method, url=target_url, headers=headers, content=body)
        stats["total_bytes"] += len(resp.content)
        stats["total_requests"] += 1
        hourly_traffic[datetime.now().strftime("%H:00")] += len(resp.content)
        return Response(content=resp.content, status_code=resp.status_code,
                        headers={k: v for k, v in resp.headers.items() if k.lower() not in _HOP})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")

# ══════════════════════════════════════════════════════════════════════════════
# HTML Pages
# ══════════════════════════════════════════════════════════════════════════════

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
.grid{position:fixed;inset:0;background-image:linear-gradient(rgba(59,130,246,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(59,130,246,0.04) 1px,transparent 1px);background-size:44px 44px;z-index:0}
.orb{position:fixed;border-radius:50%;filter:blur(90px);z-index:0;animation:fl 9s ease-in-out infinite}
.o1{width:380px;height:380px;background:rgba(59,130,246,0.07);top:-100px;right:-80px}
.o2{width:280px;height:280px;background:rgba(16,185,129,0.04);bottom:-60px;left:-60px;animation-delay:4s}
@keyframes fl{0%,100%{transform:translateY(0)}50%{transform:translateY(-18px)}}
.wrap{position:relative;z-index:10;width:100%;max-width:400px}
.card{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:38px 34px 34px;backdrop-filter:blur(24px);box-shadow:0 0 80px rgba(59,130,246,0.07),0 20px 60px rgba(0,0,0,.5)}
.brand{display:flex;align-items:center;gap:14px;margin-bottom:28px}
.brand-img{width:48px;height:48px;border-radius:13px;overflow:hidden;border:1px solid var(--border);box-shadow:0 0 20px rgba(59,130,246,0.3);flex-shrink:0}
.brand-img img{width:100%;height:100%;object-fit:cover}
.brand-name{font-size:16px;font-weight:700;color:var(--text)}
.brand-sub{font-size:11px;color:var(--dim);margin-top:2px}
h1{font-size:21px;font-weight:700;color:var(--text);margin-bottom:5px;letter-spacing:-.02em}
.sub{font-size:12px;color:var(--mid);margin-bottom:24px;line-height:1.6}
.hint{display:flex;align-items:center;gap:10px;background:rgba(59,130,246,0.07);border:1px solid rgba(59,130,246,0.15);border-radius:10px;padding:10px 14px;margin-bottom:20px}
.hint-label{font-size:11px;color:var(--dim);flex:1}
.hint-val{font-family:ui-monospace,monospace;font-size:14px;font-weight:700;color:var(--accent);background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.25);padding:3px 11px;border-radius:7px;cursor:pointer;transition:.15s;letter-spacing:.08em}
.hint-val:hover{background:rgba(59,130,246,0.22)}
.field{margin-bottom:18px}
.field label{display:block;font-size:10.5px;font-weight:600;color:var(--mid);margin-bottom:7px;text-transform:uppercase;letter-spacing:.06em}
.inp-wrap{position:relative}
input[type=password]{width:100%;padding:13px 44px 13px 16px;border-radius:11px;border:1px solid var(--border);background:rgba(0,0,0,.3);color:var(--text);font-family:inherit;font-size:14px;outline:none;transition:.2s}
input[type=password]:focus{border-color:rgba(59,130,246,.55);background:rgba(0,0,0,.4);box-shadow:0 0 0 3px rgba(59,130,246,.1)}
.ic{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--dim);font-size:18px;pointer-events:none;transition:.2s}
input:focus+.ic{color:var(--accent)}
.err{display:none;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:12px;color:#F87171;align-items:center;gap:8px}
.err.show{display:flex}
.btn{width:100%;padding:13px;border-radius:11px;border:none;cursor:pointer;background:linear-gradient(135deg,#2563EB,#1D4ED8);color:#fff;font-family:inherit;font-size:14px;font-weight:600;display:flex;align-items:center;justify-content:center;gap:8px;box-shadow:0 4px 20px rgba(37,99,235,.4);transition:.2s;position:relative;overflow:hidden}
.btn::before{content:'';position:absolute;inset:0;background:rgba(255,255,255,.08);opacity:0;transition:.2s}
.btn:hover::before{opacity:1}
.btn:disabled{opacity:.5;cursor:not-allowed}
.footer{margin-top:22px;padding-top:18px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:center;gap:8px;font-size:11px;color:var(--dim)}
.footer a{color:var(--accent);font-weight:600;text-decoration:none;display:flex;align-items:center;gap:4px}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="bg"></div><div class="grid"></div>
<div class="orb o1"></div><div class="orb o2"></div>
<div class="wrap">
  <div class="card">
    <div class="brand">
      <div class="brand-img"><img src="https://yt3.googleusercontent.com/vA6bYj1V386YmibpWRNFJtsRRqwfY_U9wnb7gmW90eRVXyNB7gAfjj1XPs5UX0cdKdQprrI=s160-c-k-c0x00ffffff-no-rj" alt="Panel"></div>
      <div><div class="brand-name">Panel</div><div class="brand-sub">RVG Gateway · v8.1</div></div>
    </div>
    <h1>ورود به پنل</h1>
    <p class="sub">رمز عبور را برای دسترسی به داشبورد وارد کنید</p>
    <div class="err" id="err"><i class="ti ti-alert-circle"></i><span id="err-text"></span></div>
    <div class="hint">
      <span class="hint-label">رمز پیش‌فرض سیستم</span>
      <span class="hint-val" onclick="document.getElementById('pw').value='123456';document.getElementById('pw').focus()">123456</span>
    </div>
    <form id="form">
      <div class="field">
        <label>رمز عبور</label>
        <div class="inp-wrap">
          <input type="password" id="pw" placeholder="رمز عبور را وارد کنید" autofocus required>
          <i class="ti ti-lock ic"></i>
        </div>
      </div>
      <button class="btn" type="submit" id="btn"><i class="ti ti-login-2"></i> ورود به داشبورد</button>
    </form>
    <div class="footer">کانال رسمی<a href="https://t.me/CodeBoxo" target="_blank"><i class="ti ti-brand-telegram"></i>@CodeBoxo</a></div>
  </div>
</div>
<script>
document.getElementById('form').addEventListener('submit',async e=>{
  e.preventDefault();
  const btn=document.getElementById('btn'),err=document.getElementById('err'),et=document.getElementById('err-text');
  err.classList.remove('show');btn.disabled=true;
  btn.innerHTML='<i class="ti ti-loader-2" style="animation:spin 1s linear infinite"></i> در حال ورود...';
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('pw').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'خطا');}
    location.href='/dashboard';
  }catch(e){
    et.textContent=e.message;err.classList.add('show');
    btn.disabled=false;btn.innerHTML='<i class="ti ti-login-2"></i> ورود به داشبورد';
  }
});
</script>
</body></html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RVG Gateway · Panel</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#060f1d;--bg2:#0a1628;--bg3:#0e1e35;
  --card:#0d1b2e;--card-b:rgba(59,130,246,0.13);--card-bh:rgba(59,130,246,0.28);
  --accent:#3B82F6;--accent2:#60A5FA;--accent-d:rgba(59,130,246,0.12);
  --green:#10B981;--green-bg:rgba(16,185,129,0.1);--green-t:#34D399;
  --red:#EF4444;--red-bg:rgba(239,68,68,0.1);--red-t:#F87171;
  --amber:#F59E0B;--amber-bg:rgba(245,158,11,0.1);--amber-t:#FCD34D;
  --purple:#8B5CF6;--purple-bg:rgba(139,92,246,0.1);
  --t1:#E8F4FF;--t2:#7BAED4;--t3:#3D6B8E;
  --sidebar-w:248px;--radius:14px;
  --shadow:0 4px 24px rgba(0,0,0,0.35);
}
[data-theme="light"]{
  --bg:#F0F4FA;--bg2:#E4EDF9;--bg3:#D5E3F5;
  --card:#FFFFFF;--card-b:rgba(59,130,246,0.15);--card-bh:rgba(59,130,246,0.35);
  --accent:#2563EB;--accent2:#1D4ED8;--accent-d:rgba(37,99,235,0.08);
  --green:#059669;--green-bg:rgba(5,150,105,0.08);--green-t:#065F46;
  --red:#DC2626;--red-bg:rgba(220,38,38,0.08);--red-t:#991B1B;
  --amber:#D97706;--amber-bg:rgba(217,119,6,0.08);--amber-t:#92400E;
  --purple:#7C3AED;--purple-bg:rgba(124,58,237,0.08);
  --t1:#0F172A;--t2:#334155;--t3:#64748B;
  --sidebar-w:248px;
  --shadow:0 4px 20px rgba(0,0,0,0.1);
}
html,body{height:100%}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--t1);min-height:100vh;display:flex;font-size:14px;transition:background .3s,color .3s}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--bg3);border-radius:3px}
a{color:inherit;text-decoration:none}
.sidebar{width:var(--sidebar-w);min-height:100vh;background:var(--bg2);border-left:1px solid var(--card-b);display:flex;flex-direction:column;flex-shrink:0;position:fixed;right:0;top:0;bottom:0;z-index:200;transition:transform .25s cubic-bezier(.4,0,.2,1),background .3s,border-color .3s}
.logo{display:flex;align-items:center;gap:12px;padding:20px 16px 16px;border-bottom:1px solid var(--card-b)}
.logo-img{width:38px;height:38px;border-radius:10px;overflow:hidden;border:1px solid var(--card-b);box-shadow:0 0 14px var(--accent-d);flex-shrink:0}
.logo-img img{width:100%;height:100%;object-fit:cover}
.logo-name{font-size:13.5px;font-weight:700;color:var(--t1)}
.logo-sub{font-size:10px;color:var(--t3);margin-top:1px}
.sb-close{display:none;position:absolute;left:12px;top:20px;background:var(--accent-d);border:1px solid var(--card-b);color:var(--t2);width:30px;height:30px;border-radius:8px;font-size:16px;align-items:center;justify-content:center;cursor:pointer}
.nav-wrap{flex:1;overflow-y:auto;padding:6px 0 8px}
.nav-sec{padding:14px 14px 4px;font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--t3);font-weight:700}
.nav-it{display:flex;align-items:center;gap:9px;padding:9px 14px;color:var(--t3);font-size:12.5px;cursor:pointer;border-right:2px solid transparent;transition:all .15s;margin:1px 6px;border-radius:9px}
.nav-it i{font-size:16px;width:18px;text-align:center;flex-shrink:0}
.nav-it:hover{background:var(--accent-d);color:var(--t2)}
.nav-it.on{background:var(--accent-d);color:var(--t1);border-right-color:var(--accent);font-weight:600}
.nav-badge{margin-right:auto;background:rgba(59,130,246,0.15);color:var(--accent2);font-size:9px;padding:1px 6px;border-radius:20px;font-weight:700}
.sb-foot{padding:12px 14px;border-top:1px solid var(--card-b)}
.tg-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:linear-gradient(135deg,#0098e6,#0077bb);color:#fff;border-radius:9px;padding:10px;font-size:12.5px;font-weight:600;font-family:inherit;border:none;cursor:pointer;width:100%;transition:.15s}
.tg-btn:hover{filter:brightness(1.1)}
.theme-btn{display:flex;align-items:center;justify-content:center;gap:7px;background:var(--accent-d);color:var(--t2);border-radius:9px;padding:8px;font-size:12px;font-weight:500;font-family:inherit;border:1px solid var(--card-b);cursor:pointer;width:100%;transition:.15s;margin-bottom:7px}
.theme-btn:hover{background:var(--card-b);color:var(--t1)}
.logout-btn{display:flex;align-items:center;justify-content:center;gap:7px;background:var(--red-bg);color:var(--red-t);border-radius:9px;padding:8px;font-size:12px;font-weight:500;font-family:inherit;border:1px solid rgba(239,68,68,0.2);cursor:pointer;width:100%;transition:.15s;margin-top:6px}
.logout-btn:hover{background:rgba(239,68,68,0.2)}
.mob-top{display:none;position:fixed;top:0;right:0;left:0;height:52px;background:var(--bg2);border-bottom:1px solid var(--card-b);z-index:150;align-items:center;justify-content:space-between;padding:0 14px;transition:background .3s}
.mob-top .ml{display:flex;align-items:center;gap:9px}
.mob-logo{width:28px;height:28px;border-radius:7px;overflow:hidden}
.mob-logo img{width:100%;height:100%;object-fit:cover}
.mob-title{color:var(--t1);font-size:13px;font-weight:700}
.mob-right{display:flex;gap:6px}
.menu-btn,.theme-mob{background:var(--accent-d);border:1px solid var(--card-b);color:var(--t2);width:34px;height:34px;border-radius:8px;font-size:17px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:.15s}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:190;backdrop-filter:blur(3px)}
.overlay.show{display:block}
.main{margin-right:var(--sidebar-w);flex:1;padding:28px 28px 60px;min-width:0;transition:margin .25s}
.pg{display:none}
.pg.on{display:block;animation:fi .2s ease}
@keyframes fi{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:22px;flex-wrap:wrap;gap:12px}
.tb-title{font-size:18px;font-weight:700;color:var(--t1);display:flex;align-items:center;gap:8px;letter-spacing:-.02em}
.tb-title i{color:var(--accent);font-size:20px}
.tb-sub{font-size:11px;color:var(--t3);margin-top:4px}
.tb-right{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.badge{font-size:10px;padding:3px 10px;border-radius:20px;font-weight:700;display:inline-flex;align-items:center;gap:5px;white-space:nowrap}
.bg-green{background:var(--green-bg);color:var(--green-t)}
.bg-blue{background:var(--accent-d);color:var(--accent2)}
.bg-amber{background:var(--amber-bg);color:var(--amber-t)}
.bg-red{background:var(--red-bg);color:var(--red-t)}
.bg-purple{background:var(--purple-bg);color:#A78BFA}
.dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;display:inline-block}
.dg{background:var(--green)}.dr{background:var(--red)}.da{background:var(--amber)}.db{background:var(--accent)}
.pulse{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
.online-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);margin:0 auto;}
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin-bottom:18px}
.metric{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:17px 17px 14px;transition:all .2s;position:relative;overflow:hidden;cursor:default}
.metric::after{content:'';position:absolute;top:0;right:0;width:3px;height:100%;background:var(--accent);opacity:0;transition:.2s}
.metric:hover{border-color:var(--card-bh);transform:translateY(-2px);box-shadow:var(--shadow)}
.metric:hover::after{opacity:1}
.metric.suc::after{background:var(--green)}
.metric.dan::after{background:var(--red)}
.m-icon{width:34px;height:34px;border-radius:8px;background:var(--accent-d);display:flex;align-items:center;justify-content:center;margin-bottom:11px;color:var(--accent);font-size:17px}
.m-icon.suc{background:var(--green-bg);color:var(--green)}
.m-icon.dan{background:var(--red-bg);color:var(--red)}
.m-label{font-size:10px;color:var(--t3);margin-bottom:4px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.m-val{font-size:25px;font-weight:700;color:var(--t1);line-height:1;letter-spacing:-.02em}
.m-unit{font-size:12px;font-weight:400;color:var(--t3)}
.m-sub{font-size:10px;color:var(--t3);margin-top:6px;display:flex;align-items:center;gap:3px}
.vless-box{background:linear-gradient(135deg,var(--bg3) 0%,var(--bg2) 100%);border:1px solid var(--card-b);border-radius:16px;padding:20px 22px;margin-bottom:18px;box-shadow:var(--shadow);position:relative;overflow:hidden;transition:background .3s}
.vless-box::before{content:'';position:absolute;top:-50px;left:-50px;width:180px;height:180px;background:radial-gradient(circle,var(--accent-d),transparent 70%);pointer-events:none}
.vl-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:13px;flex-wrap:wrap;gap:8px}
.vl-title{color:var(--t2);font-size:11px;display:flex;align-items:center;gap:6px;font-weight:700;text-transform:uppercase;letter-spacing:.06em}
.vl-title i{color:var(--accent);font-size:15px}
.vl-code{background:rgba(0,0,0,.18);border:1px solid var(--card-b);border-radius:9px;padding:13px 15px;font-size:11px;font-family:ui-monospace,monospace;color:var(--accent2);word-break:break-all;line-height:1.8;letter-spacing:.01em}
[data-theme="light"] .vl-code{background:rgba(0,0,0,.04)}
.vl-actions{display:flex;gap:8px;margin-top:13px;flex-wrap:wrap}
.btn{font-family:inherit;font-size:12px;font-weight:500;border-radius:8px;padding:8px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;border:none;transition:all .15s;white-space:nowrap}
.btn i{font-size:13px}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-p{background:var(--accent);color:#fff;box-shadow:0 2px 12px rgba(59,130,246,.3)}
.btn-p:hover{background:#2563EB;box-shadow:0 4px 18px rgba(59,130,246,.4)}
.btn-o{background:transparent;border:1px solid var(--card-b);color:var(--t2)}
.btn-o:hover{background:var(--accent-d);border-color:rgba(59,130,246,.3)}
.btn-g{background:var(--accent-d);color:var(--accent2);border:1px solid rgba(59,130,246,.15)}
.btn-g:hover{background:rgba(59,130,246,.22)}
.btn-d{background:var(--red-bg);color:var(--red-t);border:1px solid rgba(239,68,68,.2)}
.btn-d:hover{background:rgba(239,68,68,.2)}
.btn-sm{padding:5px 9px;font-size:10.5px;border-radius:7px}
.card{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:18px 20px;transition:border-color .2s,background .3s}
.card:hover{border-color:var(--card-bh)}
.card-title{font-size:12.5px;font-weight:700;color:var(--t1);margin-bottom:15px;display:flex;align-items:center;gap:7px}
.card-title i{font-size:16px;color:var(--accent)}
.ml-auto{margin-right:auto}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:13px;margin-bottom:16px}
.g3{display:grid;grid-template-columns:2fr 1fr;gap:13px;margin-bottom:16px}
.mb16{margin-bottom:16px}
.sr{display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid rgba(59,130,246,0.05);font-size:12px}
.sr:last-child{border-bottom:none}
.sr-k{color:var(--t2);display:flex;align-items:center;gap:6px}
.sr-k i{font-size:13px;color:var(--t3)}
.sr-v{color:var(--t1);font-weight:600;font-size:11.5px}
.ch{position:relative;height:210px}
.ch-lg{position:relative;height:310px}
.ch-sm{position:relative;height:165px}
.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:right;font-size:9.5px;color:var(--t3);font-weight:700;padding:9px 9px;border-bottom:1px solid var(--card-b);text-transform:uppercase;letter-spacing:.07em;white-space:nowrap}
.tbl td{padding:11px 9px;border-bottom:1px solid rgba(59,130,246,0.04);font-size:12px;vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tbody tr{transition:.12s}
.tbl tbody tr:hover td{background:var(--accent-d)}
.uuid-chip{font-family:ui-monospace,monospace;font-size:9.5px;color:var(--accent2);background:var(--accent-d);padding:2px 7px;border-radius:5px;display:inline-block;letter-spacing:.02em;cursor:pointer;transition:.15s}
.uuid-chip:hover{background:rgba(59,130,246,.2)}
.ubar{height:6px;border-radius:3px;background:rgba(59,130,246,0.1);overflow:hidden;margin-bottom:3px}
.ubar-f{height:100%;border-radius:3px;transition:width .3s}
.utxt{font-size:9.5px;color:var(--t3)}
.ll{font-weight:600;color:var(--t1);font-size:12.5px}
.lm{font-size:9.5px;color:var(--t3);margin-top:2px;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.exp-chip{font-size:9px;padding:2px 7px;border-radius:5px;font-weight:700;display:inline-flex;align-items:center;gap:3px}
.ec-ok{background:var(--green-bg);color:var(--green-t)}
.ec-warn{background:var(--amber-bg);color:var(--amber-t)}
.ec-exp{background:var(--red-bg);color:var(--red-t)}
.ec-inf{background:var(--accent-d);color:var(--accent2)}
.tog{width:34px;height:19px;border-radius:19px;background:rgba(100,116,139,0.25);position:relative;cursor:pointer;transition:.2s;flex-shrink:0;border:none}
.tog::after{content:'';position:absolute;width:13px;height:13px;border-radius:50%;background:#fff;top:3px;right:3px;transition:.2s;box-shadow:0 1px 3px rgba(0,0,0,.3)}
.tog.on{background:var(--green)}
.tog.on::after{right:18px}
.form-row{display:flex;gap:9px;flex-wrap:wrap;align-items:flex-end}
.fg{display:flex;flex-direction:column;gap:5px}
.fg label{font-size:10px;color:var(--t3);font-weight:700;text-transform:uppercase;letter-spacing:.06em}
.fi,.fs{padding:9px 12px;border-radius:8px;border:1px solid var(--card-b);background:rgba(0,0,0,.18);color:var(--t1);font-family:inherit;font-size:12px;outline:none;transition:.15s;min-width:100px}
[data-theme="light"] .fi,[data-theme="light"] .fs{background:rgba(0,0,0,.04)}
.fi::placeholder{color:var(--t3)}
.fi:focus,.fs:focus{border-color:rgba(59,130,246,.45);background:rgba(0,0,0,.25);box-shadow:0 0 0 3px rgba(59,130,246,.08)}
.fs option{background:var(--bg2)}
[data-theme="light"] .fs option{background:#fff}
.cl{background:var(--accent-d);border:1px solid rgba(59,130,246,.15);border-radius:10px;padding:11px 13px;font-size:11px;color:var(--t2);display:flex;gap:9px;align-items:flex-start;line-height:1.8;margin-top:12px}
.cl i{font-size:15px;color:var(--accent);margin-top:1px;flex-shrink:0}
.cl.amber{background:var(--amber-bg);border-color:rgba(245,158,11,.2);color:var(--amber-t)}
.cl.amber i{color:var(--amber)}
.sub-box{background:rgba(139,92,246,.07);border:1px solid rgba(139,92,246,.2);border-radius:10px;padding:14px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-top:11px}
.sub-url{font-family:ui-monospace,monospace;font-size:10.5px;color:#A78BFA;word-break:break-all;flex:1}
.erow{padding:9px 0;border-bottom:1px solid rgba(59,130,246,.05)}
.erow:last-child{border-bottom:none}
.etime{color:var(--t3);font-size:9.5px;margin-bottom:3px;display:flex;align-items:center;gap:4px}
.emsg{color:var(--red-t);font-family:ui-monospace,monospace;background:var(--red-bg);padding:6px 9px;border-radius:6px;word-break:break-all;font-size:10.5px}
.spbar{height:4px;border-radius:3px;background:var(--accent-d);margin-top:5px;overflow:hidden}
.spfill{height:100%;border-radius:3px;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width 1s}
.empty{text-align:center;padding:44px 20px;color:var(--t3)}
.empty i{font-size:38px;opacity:.35;margin-bottom:10px;display:block}
.empty p{font-size:12px;margin-top:4px}
.idea-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:13px}
.idea-card{background:var(--card);border:1px solid var(--card-b);border-radius:13px;padding:17px;transition:.2s}
.idea-card:hover{border-color:var(--card-bh);transform:translateY(-2px)}
.idea-icon{width:36px;height:36px;border-radius:9px;background:var(--accent-d);display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:18px;margin-bottom:10px}
.idea-title{font-size:12.5px;font-weight:700;color:var(--t1);margin-bottom:5px}
.idea-desc{font-size:10.5px;color:var(--t3);line-height:1.8}
.ibadge{display:inline-block;margin-top:9px;font-size:9px;padding:2px 8px;border-radius:20px;font-weight:700}
.ibadge.done{background:var(--green-bg);color:var(--green-t)}
.ibadge.plan{background:var(--accent-d);color:var(--accent2)}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(40px);background:var(--card);border:1px solid var(--card-b);color:var(--t1);border-radius:10px;padding:10px 18px;font-size:12.5px;opacity:0;transition:all .25s;z-index:999;pointer-events:none;display:flex;align-items:center;gap:8px;box-shadow:var(--shadow);white-space:nowrap}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.ok{border-color:rgba(16,185,129,.3);background:var(--green-bg);color:var(--green-t)}
.toast.err{border-color:rgba(239,68,68,.3);background:var(--red-bg);color:var(--red-t)}
.dash-footer{border-top:1px solid var(--card-b);margin-top:14px;padding-top:14px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.df-text{font-size:10px;color:var(--t3)}
.df-link{font-size:11.5px;color:var(--accent2);display:flex;align-items:center;gap:5px;font-weight:600}
@media(max-width:1050px){
  .sidebar{transform:translateX(100%)}
  .sidebar.open{transform:translateX(0);box-shadow:-10px 0 40px rgba(0,0,0,.4)}
  .sb-close{display:flex}
  .main{margin-right:0;padding-top:70px}
  .mob-top{display:flex}
  .metrics{grid-template-columns:1fr 1fr}
  .g2,.g3{grid-template-columns:1fr}
  .idea-grid{grid-template-columns:1fr 1fr}
}
@media(max-width:500px){
  .metrics{grid-template-columns:1fr}
  .main{padding:62px 12px 50px}
  .idea-grid{grid-template-columns:1fr}
  .tbl th:nth-child(2),.tbl td:nth-child(2){display:none}
}
</style>
</head>
<body>
<div class="toast" id="toast"></div>
<div class="mob-top">
  <div class="ml">
    <div class="mob-logo"><img src="https://yt3.googleusercontent.com/vA6bYj1V386YmibpWRNFJtsRRqwfY_U9wnb7gmW90eRVXyNB7gAfjj1XPs5UX0cdKdQprrI=s160-c-k-c0x00ffffff-no-rj" alt="Panel"></div>
    <span class="mob-title">RVG Gateway</span>
  </div>
  <div class="mob-right">
    <button class="theme-mob" id="theme-mob-btn" onclick="toggleTheme()" title="تغییر تم"><i class="ti ti-sun" id="theme-mob-icon"></i></button>
    <button class="menu-btn" id="open-sb"><i class="ti ti-menu-2"></i></button>
  </div>
</div>
<div class="overlay" id="overlay"></div>
<aside class="sidebar" id="sb">
  <button class="sb-close" id="close-sb"><i class="ti ti-x"></i></button>
  <div class="logo">
    <div class="logo-img"><img src="https://yt3.googleusercontent.com/vA6bYj1V386YmibpWRNFJtsRRqwfY_U9wnb7gmW90eRVXyNB7gAfjj1XPs5UX0cdKdQprrI=s160-c-k-c0x00ffffff-no-rj" alt="Panel"></div>
    <div><div class="logo-name">Panel</div><div class="logo-sub">RVG Gateway · v8.1</div></div>
  </div>
  <div class="nav-wrap">
    <div class="nav-sec">پنل</div>
    <div class="nav-it on" data-pg="overview"><i class="ti ti-layout-dashboard"></i> داشبورد</div>
    <div class="nav-it" data-pg="links"><i class="ti ti-link-plus"></i> مدیریت لینک‌ها <span class="nav-badge" id="links-nb">0</span></div>
    <div class="nav-it" data-pg="subscriptions"><i class="ti ti-rss"></i> سابسکریپشن</div>
    <div class="nav-it" data-pg="traffic"><i class="ti ti-chart-area"></i> ترافیک</div>
    <div class="nav-it" data-pg="connections"><i class="ti ti-plug-connected"></i> اتصالات <span class="nav-badge" id="conns-nb">0</span></div>
    <div class="nav-sec">سیستم</div>
    <div class="nav-it" data-pg="security"><i class="ti ti-shield-lock"></i> امنیت</div>
    <div class="nav-it" data-pg="errors"><i class="ti ti-alert-triangle"></i> خطاها</div>
    <div class="nav-it" data-pg="ideas"><i class="ti ti-bulb"></i> ایده‌ها</div>
    <div class="nav-it" data-pg="testws"><i class="ti ti-wifi"></i> تست WebSocket</div>
    <div class="nav-it" data-pg="settings"><i class="ti ti-settings"></i> تنظیمات</div>
  </div>
  <div class="sb-foot">
    <button class="theme-btn" onclick="toggleTheme()"><i class="ti ti-moon" id="theme-icon"></i> <span id="theme-label">تم روشن</span></button>
    <a class="tg-btn" href="https://t.me/CodeBoxo" target="_blank" rel="noopener"><i class="ti ti-brand-telegram"></i> @CodeBoxo</a>
    <button class="logout-btn" id="logout-btn"><i class="ti ti-logout"></i> خروج</button>
  </div>
</aside>
<main class="main">

<!-- OVERVIEW -->
<section class="pg on" id="pg-overview">
  <div class="topbar">
    <div><div class="tb-title"><i class="ti ti-layout-dashboard"></i> داشبورد</div><div class="tb-sub" id="last-upd">در حال بارگذاری...</div></div>
    <div class="tb-right">
      <span class="badge bg-green"><span class="dot dg pulse"></span> فعال</span>
      <span class="badge bg-blue" id="uptime-badge">—</span>
      <button class="btn btn-p btn-sm" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button>
    </div>
  </div>
  <div class="metrics">
    <div class="metric"><div class="m-icon"><i class="ti ti-plug-connected"></i></div><div class="m-label">اتصالات فعال</div><div class="m-val" id="m-conns">—</div><div class="m-sub"><span class="dot dg pulse"></span> WebSocket زنده</div></div>
    <div class="metric"><div class="m-icon"><i class="ti ti-transfer"></i></div><div class="m-label">کل ترافیک</div><div class="m-val" id="m-traffic">—<span class="m-unit">MB</span></div><div class="m-sub">از راه‌اندازی</div></div>
    <div class="metric suc"><div class="m-icon suc"><i class="ti ti-link"></i></div><div class="m-label">لینک‌های فعال</div><div class="m-val" id="m-alinks">—</div><div class="m-sub" id="m-lsub">از کل</div></div>
    <div class="metric dan"><div class="m-icon dan"><i class="ti ti-alert-circle"></i></div><div class="m-label">خطاها</div><div class="m-val" id="m-errs">—</div><div class="m-sub">ثبت شده</div></div>
  </div>
  <div class="vless-box">
    <div class="vl-header">
      <div class="vl-title"><i class="ti ti-link"></i> لینک پیش‌فرض (بدون محدودیت)</div>
      <span class="badge bg-blue"><span class="dot db"></span> TLS 443 · WS</span>
    </div>
    <div class="vl-code" id="vless-main">در حال دریافت...</div>
    <div class="vl-actions">
      <button class="btn btn-p" onclick="cpText('vless-main')"><i class="ti ti-copy"></i> کپی</button>
      <button class="btn btn-g" onclick="qrFor('vless-main')"><i class="ti ti-qrcode"></i> QR</button>
      <button class="btn btn-o" onclick="navTo('links')"><i class="ti ti-link-plus"></i> لینک محدود</button>
      <button class="btn btn-o" onclick="navTo('subscriptions')"><i class="ti ti-rss"></i> سابسکریپشن</button>
    </div>
  </div>
  <div class="g3">
    <div class="card"><div class="card-title"><i class="ti ti-chart-area"></i> ترافیک ساعتی (MB)</div><div class="ch"><canvas id="ch1"></canvas></div></div>
    <div class="card"><div class="card-title"><i class="ti ti-chart-donut"></i> توزیع</div><div class="ch-sm"><canvas id="ch2"></canvas></div></div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-title"><i class="ti ti-activity"></i> وضعیت سرویس</div>
      <div class="sr"><span class="sr-k"><i class="ti ti-shield-check"></i> UUID Auth</span><span class="sr-v" style="color:var(--green-t)">● فعال · سخت‌گیرانه</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-circle-check"></i> VLESS / WS Tunnel</span><span class="sr-v" style="color:var(--green-t)">● فعال</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-circle-check"></i> HTTP Proxy</span><span class="sr-v" style="color:var(--green-t)">● فعال</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-rss"></i> Subscription API</span><span class="sr-v" style="color:var(--green-t)">● فعال</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-clock"></i> آپتایم</span><span class="sr-v" id="uptime-inline">—</span></div>
      <div class="sr" style="flex-direction:column;align-items:flex-start;gap:4px">
        <div style="width:100%;display:flex;justify-content:space-between"><span class="sr-k"><i class="ti ti-gauge"></i> بار نسبی</span><span class="sr-v" id="bw-pct">—%</span></div>
        <div class="spbar" style="width:100%"><div class="spfill" id="bw-bar" style="width:0%"></div></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title"><i class="ti ti-list"></i> خلاصه لینک‌ها <span class="ml-auto badge bg-blue" id="lsummary-badge">۰</span></div>
      <div id="lsummary">—</div>
    </div>
  </div>
  <div class="dash-footer">
    <span class="df-text">Panel RVG Gateway v8.1 · Railway · 2025</span>
    <a class="df-link" href="https://t.me/CodeBoxo" target="_blank"><i class="ti ti-brand-telegram"></i> t.me/CodeBoxo</a>
  </div>
</section>

<!-- LINKS -->
<section class="pg" id="pg-links">
  <div class="topbar">
    <div><div class="tb-title"><i class="ti ti-link-plus"></i> مدیریت لینک‌ها</div><div class="tb-sub">ساخت و مدیریت کانفیگ با سهمیه و تاریخ انقضا</div></div>
    <div class="tb-right"><span class="badge bg-blue" id="links-pg-cnt">۰ لینک</span></div>
  </div>
  <div class="card mb16">
    <div class="card-title"><i class="ti ti-plus"></i> ساخت لینک جدید</div>
    <div class="form-row">
      <div class="fg" style="flex:1;min-width:150px"><label>عنوان لینک</label><input class="fi" id="nl-label" placeholder="مثلاً: کاربر علی" style="width:100%"></div>
      <div class="fg"><label>سهمیه ترافیک</label><input class="fi" id="nl-val" type="number" min="0" step="0.1" placeholder="0=بی‌نهایت" style="width:120px"></div>
      <div class="fg"><label>واحد</label><select class="fs" id="nl-unit"><option value="GB">GB</option><option value="MB" selected>MB</option></select></div>
      <div class="fg"><label>انقضا (روز)</label><input class="fi" id="nl-exp" type="number" min="0" step="1" placeholder="0=بی‌نهایت" style="width:100px"></div>
      <div class="fg" style="flex:1;min-width:130px"><label>یادداشت</label><input class="fi" id="nl-note" placeholder="اختیاری" style="width:100%"></div>
      <button class="btn btn-p" onclick="createLink()"><i class="ti ti-link-plus"></i> ساخت</button>
    </div>
    <div class="cl"><i class="ti ti-info-circle"></i><span>UUID هر لینک کاملاً رندوم است. فقط UUID‌های ثبت‌شده در سیستم می‌توانند اتصال برقرار کنند.</span></div>
  </div>
  <!-- نوار جستجوی پیشرفته -->
  <div class="card mb16">
    <div class="card-title"><i class="ti ti-search"></i> جستجوی پیشرفته</div>
    <div class="form-row">
      <div class="fg" style="flex:2;min-width:200px">
        <label>جستجوی نام یا UUID</label>
        <input class="fi" id="link-search" placeholder="متن جستجو..." style="width:100%" oninput="filterLinks()">
      </div>
      <div class="fg" style="min-width:150px">
        <label>فیلتر وضعیت</label>
        <select class="fs" id="link-status-filter" onchange="filterLinks()">
          <option value="all">همه</option>
          <option value="active">فعال</option>
          <option value="expired">منقضی</option>
          <option value="disabled">غیرفعال</option>
          <option value="online">آنلاین</option>
        </select>
      </div>
      <div class="fg" style="min-width:150px">
        <label>مرتب‌سازی</label>
        <select class="fs" id="link-sort" onchange="filterLinks()">
          <option value="newest">جدیدترین</option>
          <option value="oldest">قدیمی‌ترین</option>
          <option value="name">نام (الفبا)</option>
          <option value="usage">مصرف (زیاد→کم)</option>
          <option value="expiry">تاریخ انقضا</option>
        </select>
      </div>
      <button class="btn btn-o" onclick="clearFilters()"><i class="ti ti-filter-off"></i> پاک‌کردن فیلترها</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title"><i class="ti ti-list"></i> لینک‌ها</div>
    <div style="overflow-x:auto">
      <table class="tbl">
        <thead><tr><th>عنوان / یادداشت</th><th style="text-align:center">وضعیت اتصال</th><th>UUID</th><th>مصرف / سهمیه</th><th>انقضا</th><th>وضعیت</th><th>عملیات</th></tr></thead>
        <tbody id="links-tb"></tbody>
      </table>
    </div>
    <div class="empty" id="links-empty" style="display:none"><i class="ti ti-link-off"></i><p>هیچ لینکی با این مشخصات یافت نشد</p></div>
  </div>
</section>

<!-- SUBSCRIPTIONS -->
<section class="pg" id="pg-subscriptions">
  <div class="topbar"><div><div class="tb-title"><i class="ti ti-rss"></i> سابسکریپشن</div><div class="tb-sub">لینک‌های اشتراک برای اپ‌های v2ray</div></div></div>
  <div class="g2">
    <div class="card">
      <div class="card-title"><i class="ti ti-rss"></i> سابسکریپشن تکی</div>
      <p style="font-size:11.5px;color:var(--t3);line-height:1.8;margin-bottom:12px">هر لینک URL سابسکریپشن مخصوص به خود دارد که در Hiddify، Shadowrocket، v2rayN و NekoBox قابل استفاده است.</p>
      <div class="cl"><i class="ti ti-info-circle"></i><span>آدرس سابسکریپشن هر کانفیگ را از جدول لینک‌ها با کلیک روی آیکون <i class="ti ti-rss"></i> کپی کنید.</span></div>
    </div>
    <div class="card">
      <div class="card-title"><i class="ti ti-database"></i> سابسکریپشن کامل (ادمین)</div>
      <p style="font-size:11.5px;color:var(--t3);line-height:1.8;margin-bottom:4px">شامل تمام لینک‌های فعال و منقضی‌نشده.</p>
      <div class="sub-box"><span class="sub-url" id="sub-all-url">در حال دریافت...</span><div style="display:flex;gap:6px"><button class="btn btn-sm btn-g" onclick="cpSubAll()"><i class="ti ti-copy"></i></button><button class="btn btn-sm btn-g" onclick="window.open(location.protocol+'//'+location.host+'/sub-all')"><i class="ti ti-external-link"></i></button></div></div>
      <div class="cl amber" style="margin-top:11px"><i class="ti ti-alert-triangle"></i><span>این آدرس فقط در مرورگری که به پنل وارد شده کار می‌کند (نیاز به کوکی سشن).</span></div>
    </div>
  </div>
  <div class="card">
    <div class="card-title"><i class="ti ti-list"></i> لینک‌های فعال + آدرس سابسکریپشن</div>
    <div id="sub-list">در حال بارگذاری...</div>
  </div>
</section>

<!-- TRAFFIC -->
<section class="pg" id="pg-traffic">
  <div class="topbar"><div><div class="tb-title"><i class="ti ti-chart-area"></i> ترافیک</div></div><div class="tb-right"><button class="btn btn-p btn-sm" onclick="refreshAll()"><i class="ti ti-refresh"></i></button></div></div>
  <div class="metrics" style="grid-template-columns:repeat(3,1fr)">
    <div class="metric"><div class="m-icon"><i class="ti ti-database"></i></div><div class="m-label">کل</div><div class="m-val" id="t-traffic">—<span class="m-unit">MB</span></div></div>
    <div class="metric"><div class="m-icon"><i class="ti ti-arrow-up"></i></div><div class="m-label">میانگین ساعتی</div><div class="m-val" id="t-avg">—<span class="m-unit">MB</span></div></div>
    <div class="metric"><div class="m-icon"><i class="ti ti-chart-bar"></i></div><div class="m-label">پیک ساعتی</div><div class="m-val" id="t-peak">—<span class="m-unit">MB</span></div></div>
  </div>
  <div class="card"><div class="card-title"><i class="ti ti-chart-area"></i> نمودار ترافیک ساعتی</div><div class="ch-lg"><canvas id="ch3"></canvas></div></div>
</section>

<!-- CONNECTIONS -->
<section class="pg" id="pg-connections">
  <div class="topbar">
    <div><div class="tb-title"><i class="ti ti-plug-connected"></i> اتصالات</div><div class="tb-sub">کاربران آنلاین</div></div>
    <div class="tb-right">
      <span class="badge bg-green" id="conns-live">—</span>
      <button class="btn btn-p btn-sm" onclick="loadConns()"><i class="ti ti-refresh"></i> رفرش</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title"><i class="ti ti-users"></i> کاربران متصل</div>
    <div style="overflow-x:auto">
      <table class="tbl">
        <thead><tr><th>کاربر</th><th style="text-align:center">وضعیت</th></tr></thead>
        <tbody id="conns-tbody"></tbody>
      </table>
    </div>
    <div class="empty" id="conns-empty" style="display:none"><i class="ti ti-plug-off"></i><p>هیچ کاربری آنلاین نیست</p></div>
  </div>
</section>

<!-- SECURITY -->
<section class="pg" id="pg-security">
  <div class="topbar"><div><div class="tb-title"><i class="ti ti-shield-lock"></i> امنیت</div></div></div>
  <div class="g2">
    <div class="card">
      <div class="card-title"><i class="ti ti-lock"></i> رمزنگاری</div>
      <div class="sr"><span class="sr-k"><i class="ti ti-certificate"></i> TLS/HTTPS</span><span class="sr-v" style="color:var(--green-t)">● فعال (443)</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-fingerprint"></i> Fingerprint</span><span class="sr-v">Chrome Spoof</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-network"></i> پروتکل</span><span class="sr-v">VLESS/WS</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-key"></i> هش رمز</span><span class="sr-v">SHA-256+Salt</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-cookie"></i> سشن</span><span class="sr-v">HttpOnly · 7 روز</span></div>
    </div>
    <div class="card">
      <div class="card-title"><i class="ti ti-shield-check"></i> کنترل دسترسی</div>
      <div class="sr"><span class="sr-k"><i class="ti ti-id-badge"></i> UUID Auth سخت‌گیرانه</span><span class="sr-v" style="color:var(--green-t)">● فعال v8.1</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-toggle-right"></i> فعال/غیرفعال لینک</span><span class="sr-v" style="color:var(--green-t)">● فعال</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-gauge"></i> سهمیه ترافیک</span><span class="sr-v" style="color:var(--green-t)">● فعال</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-calendar-x"></i> تاریخ انقضا</span><span class="sr-v" style="color:var(--green-t)">● فعال</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-ban"></i> قطع خودکار</span><span class="sr-v" style="color:var(--green-t)">● فعال</span></div>
    </div>
  </div>
  <div class="cl"><i class="ti ti-info-circle"></i><span>در v8.1 هر UUID ناشناخته، حذف‌شده یا غیرفعال قبل از accept پروتکل VLESS رد می‌شود. اتصال بلافاصله با کد 1008 قطع می‌گردد.</span></div>
</section>

<!-- ERRORS -->
<section class="pg" id="pg-errors">
  <div class="topbar"><div><div class="tb-title"><i class="ti ti-alert-triangle"></i> خطاها</div></div><div class="tb-right"><span class="badge bg-red" id="errs-badge">۰</span><button class="btn btn-p btn-sm" onclick="refreshAll()"><i class="ti ti-refresh"></i></button></div></div>
  <div class="card"><div class="card-title"><i class="ti ti-bug"></i> لاگ خطاها</div><div id="errs-full">—</div></div>
</section>

<!-- IDEAS -->
<section class="pg" id="pg-ideas">
  <div class="topbar"><div><div class="tb-title"><i class="ti ti-bulb"></i> ایده‌ها</div></div></div>
  <div class="idea-grid">
    <div class="idea-card"><div class="idea-icon" style="background:var(--green-bg);color:var(--green)"><i class="ti ti-shield-check"></i></div><div class="idea-title">UUID Auth سخت‌گیرانه</div><div class="idea-desc">UUID ناشناخته، حذف‌شده یا غیرفعال قبل از هر پردازشی رد می‌شود.</div><span class="ibadge done">آماده v8.1</span></div>
    <div class="idea-card"><div class="idea-icon" style="background:var(--green-bg);color:var(--green)"><i class="ti ti-device-floppy"></i></div><div class="idea-title">ذخیره دائمی JSON</div><div class="idea-desc">اطلاعات لینک‌ها و رمز عبور روی فایل ذخیره و با restart حفظ می‌شوند.</div><span class="ibadge done">آماده v8</span></div>
    <div class="idea-card"><div class="idea-icon" style="background:var(--green-bg);color:var(--green)"><i class="ti ti-rocket"></i></div><div class="idea-title">Relay بهینه</div><div class="idea-desc">بافر 256KB، TCP_NODELAY، drain هوشمند و relay موازی برای حداکثر throughput.</div><span class="ibadge done">آماده v8.1</span></div>
    <div class="idea-card"><div class="idea-icon" style="background:var(--green-bg);color:var(--green)"><i class="ti ti-sun"></i></div><div class="idea-title">تم روشن / تاریک</div><div class="idea-desc">سویچ بین دارک و لایت مود با ذخیره خودکار تنظیم.</div><span class="ibadge done">آماده v8</span></div>
    <div class="idea-card"><div class="idea-icon"><i class="ti ti-database"></i></div><div class="idea-title">Redis Persistence</div><div class="idea-desc">اتصال به Redis برای ذخیره‌سازی سریع‌تر و اشتراک state بین instance‌ها.</div><span class="ibadge plan">پیشنهادی</span></div>
    <div class="idea-card"><div class="idea-icon"><i class="ti ti-brand-telegram"></i></div><div class="idea-title">اعلان تلگرامی</div><div class="idea-desc">ارسال پیام هنگام رسیدن مصرف به ۸۰٪ و ۱۰۰٪ سهمیه از طریق Bot API.</div><span class="ibadge plan">پیشنهادی</span></div>
  </div>
</section>

<!-- TEST WS -->
<section class="pg" id="pg-testws">
  <div class="topbar"><div><div class="tb-title"><i class="ti ti-wifi"></i> تست WebSocket</div></div></div>
  <div class="card" style="max-width:660px">
    <div class="cl amber" style="margin-top:0;margin-bottom:12px"><i class="ti ti-alert-triangle"></i><span>فقط UUID‌های ثبت‌شده و فعال اتصال برقرار می‌کنند. UUID رندوم رد خواهد شد.</span></div>
    <div class="form-row" style="margin-bottom:12px">
      <div class="fg" style="flex:1"><label>UUID (باید در لینک‌ها وجود داشته باشد)</label><input class="fi" id="ws-uuid" placeholder="UUID یک لینک فعال را وارد کنید" style="width:100%"></div>
      <button class="btn btn-p" onclick="wsConn()"><i class="ti ti-plug-connected"></i> اتصال</button>
      <button class="btn btn-d" onclick="wsDisc()"><i class="ti ti-plug-x"></i> قطع</button>
    </div>
    <div class="form-row" style="margin-bottom:12px">
      <input class="fi" id="ws-msg" placeholder="پیام تست..." style="flex:1">
      <button class="btn btn-o" onclick="wsSend()"><i class="ti ti-send"></i> ارسال</button>
    </div>
    <div style="background:rgba(0,0,0,.3);border:1px solid var(--card-b);border-radius:10px;padding:14px;height:250px;overflow-y:auto;font-family:ui-monospace,monospace;font-size:10.5px;line-height:1.9" id="ws-log">
      <p style="color:var(--t3)">منتظر اتصال...</p>
    </div>
  </div>
</section>

<!-- SETTINGS -->
<section class="pg" id="pg-settings">
  <div class="topbar"><div><div class="tb-title"><i class="ti ti-settings"></i> تنظیمات</div></div></div>
  <div class="g2">
    <div class="card">
      <div class="card-title"><i class="ti ti-server"></i> اطلاعات سرور</div>
      <div class="sr"><span class="sr-k"><i class="ti ti-world"></i> دامنه</span><span class="sr-v" id="set-host">—</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-route"></i> پورت</span><span class="sr-v">443 (TLS)</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-versions"></i> نسخه</span><span class="sr-v">v8.2</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-brand-fastapi"></i> فریم‌ورک</span><span class="sr-v">FastAPI + Uvicorn</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-cloud"></i> پلتفرم</span><span class="sr-v">Railway</span></div>
      <div class="sr"><span class="sr-k"><i class="ti ti-device-floppy"></i> ذخیره‌سازی</span><span class="sr-v">JSON File (/data)</span></div>
    </div>
    <div class="card">
      <div class="card-title"><i class="ti ti-key"></i> تغییر رمز عبور</div>
      <div class="fg" style="margin-bottom:11px"><label>رمز فعلی</label><input class="fi" type="password" id="cp-cur" placeholder="رمز فعلی" style="width:100%"></div>
      <div class="fg" style="margin-bottom:11px"><label>رمز جدید</label><input class="fi" type="password" id="cp-new" placeholder="حداقل ۴ کاراکتر" style="width:100%"></div>
      <div class="fg" style="margin-bottom:14px"><label>تکرار رمز جدید</label><input class="fi" type="password" id="cp-cf" placeholder="تکرار رمز جدید" style="width:100%"></div>
      <button class="btn btn-p" onclick="changePw()" style="width:100%;justify-content:center"><i class="ti ti-key"></i> تغییر رمز</button>
      <div class="cl" style="margin-top:11px"><i class="ti ti-info-circle"></i><span>رمز پیش‌فرض: <b>123456</b> · پس از تغییر، سشن‌های دیگر باطل می‌شوند.</span></div>
    </div>
  </div>
</section>

</main>
<script>
let isDark=localStorage.getItem('rvg-theme')!=='light';
function applyTheme(dark){
  document.documentElement.setAttribute('data-theme',dark?'dark':'light');
  const icon=dark?'ti-sun':'ti-moon',label=dark?'تم روشن':'تم تاریک';
  document.getElementById('theme-icon').className='ti '+icon;
  document.getElementById('theme-label').textContent=label;
  const mobI=document.getElementById('theme-mob-icon');
  if(mobI)mobI.className='ti '+icon;
}
function toggleTheme(){isDark=!isDark;localStorage.setItem('rvg-theme',isDark?'dark':'light');applyTheme(isDark)}
applyTheme(isDark);

function toast(msg,type=''){
  const t=document.getElementById('toast');
  t.textContent=msg;t.className='toast show'+(type?' '+type:'');
  setTimeout(()=>t.classList.remove('show'),2400);
}
function fmt(n){return n>=1000?(n/1000).toFixed(1)+'k':n}
function fmtB(b){if(!b||b===0)return '0 B';if(b<1024)return b+' B';if(b<1024**2)return (b/1024).toFixed(1)+' KB';if(b<1024**3)return (b/1024**2).toFixed(2)+' MB';return (b/1024**3).toFixed(2)+' GB'}
function toFa(n){return n.toString().replace(/\d/g,d=>'۰۱۲۳۴۵۶۷۸۹'[d])}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function daysLeft(exp){if(!exp)return null;return Math.ceil((new Date(exp)-new Date())/(864e5))}
function expChip(exp,expired){
  if(expired)return '<span class="exp-chip ec-exp"><i class="ti ti-calendar-x"></i> منقضی</span>';
  if(!exp)return '<span class="exp-chip ec-inf"><i class="ti ti-infinity"></i> بی‌نهایت</span>';
  const d=daysLeft(exp);
  if(d<=0)return '<span class="exp-chip ec-exp"><i class="ti ti-calendar-x"></i> منقضی</span>';
  if(d<=3)return `<span class="exp-chip ec-warn"><i class="ti ti-alert-triangle"></i> ${toFa(d)} روز</span>`;
  return `<span class="exp-chip ec-ok"><i class="ti ti-calendar-check"></i> ${toFa(d)} روز</span>`;
}

async function checkAuth(){try{const r=await fetch('/api/me');const d=await r.json();if(!d.authenticated)location.href='/login';}catch(e){location.href='/login'}}
async function logout(){try{await fetch('/api/logout',{method:'POST'})}catch(e){}location.href='/login'}
document.getElementById('logout-btn').addEventListener('click',logout);

async function changePw(){
  const cur=document.getElementById('cp-cur').value,nw=document.getElementById('cp-new').value,cf=document.getElementById('cp-cf').value;
  if(!cur||!nw||!cf){toast('همه فیلدها را پر کنید','err');return}
  if(nw.length<4){toast('رمز جدید حداقل ۴ کاراکتر','err');return}
  if(nw!==cf){toast('تکرار رمز اشتباه است','err');return}
  try{
    const r=await authF('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});
    const d=await r.json().catch(()=>({}));
    if(!r.ok)throw new Error(d.detail||'خطا');
    toast('رمز عبور تغییر کرد','ok');
    ['cp-cur','cp-new','cp-cf'].forEach(id=>document.getElementById(id).value='');
  }catch(e){toast('✗ '+e.message,'err')}
}

const sb=document.getElementById('sb'),overlay=document.getElementById('overlay');
function openSb(){sb.classList.add('open');overlay.classList.add('show')}
function closeSb(){sb.classList.remove('open');overlay.classList.remove('show')}
document.getElementById('open-sb').addEventListener('click',openSb);
document.getElementById('close-sb').addEventListener('click',closeSb);
overlay.addEventListener('click',closeSb);

function navTo(name){
  document.querySelectorAll('.nav-it').forEach(n=>n.classList.toggle('on',n.dataset.pg===name));
  document.querySelectorAll('.pg').forEach(p=>p.classList.toggle('on',p.id==='pg-'+name));
  if(name==='links'){loadLinks();}
  if(name==='connections')loadConns();
  if(name==='errors')loadErrs();
  if(name==='subscriptions')loadSubs();
  closeSb();window.scrollTo({top:0,behavior:'smooth'});
}
document.querySelectorAll('.nav-it').forEach(el=>el.addEventListener('click',()=>navTo(el.dataset.pg)));

async function authF(url,opts){
  const r=await fetch(url,opts);
  if(r.status===401){location.href='/login';throw new Error('unauthorized')}
  return r;
}

let prevTraf=0,ch1,ch2,ch3;
let onlineUuids = new Set();
let allLinks = []; // ذخیره همه لینک‌ها برای فیلتر

async function updateOnlineStatus(){
  try {
    const r = await authF('/api/connections');
    const d = await r.json();
    onlineUuids = new Set((d.users || []).map(u => u.uuid));
    document.getElementById('conns-nb').textContent = onlineUuids.size;
  } catch(e) { console.error(e); }
}

async function fetchStats(){
  try{
    const r=await authF('/stats'),d=await r.json();
    document.getElementById('m-conns').textContent=d.active_connections;
    document.getElementById('conns-nb').textContent=d.active_connections;
    document.getElementById('m-traffic').innerHTML=d.total_traffic_mb.toFixed(1)+'<span class="m-unit">MB</span>';
    document.getElementById('m-alinks').textContent=d.active_links??'—';
    document.getElementById('m-lsub').textContent='از '+d.links_count+' لینک';
    document.getElementById('m-errs').textContent=d.total_errors;
    document.getElementById('errs-badge').textContent=d.total_errors+' خطا';
    document.getElementById('uptime-inline').textContent=d.uptime;
    document.getElementById('uptime-badge').textContent='Railway · '+d.uptime;
    document.getElementById('last-upd').textContent='آخرین بروزرسانی: '+new Date().toLocaleTimeString('fa-IR');
    document.getElementById('t-traffic').innerHTML=d.total_traffic_mb.toFixed(1)+'<span class="m-unit">MB</span>';
    const delta=d.total_traffic_mb-prevTraf,pct=Math.min(100,Math.round((delta/50)*100));
    document.getElementById('bw-pct').textContent=pct+'%';
    document.getElementById('bw-bar').style.width=pct+'%';
    prevTraf=d.total_traffic_mb;
    if(d.hourly){
      const labels=Object.keys(d.hourly).sort(),vals=labels.map(k=>+(d.hourly[k]/1024**2).toFixed(2));
      [ch1,ch3].forEach(c=>{if(!c)return;c.data.labels=labels;c.data.datasets[0].data=vals;c.update()});
      if(vals.length){const avg=vals.reduce((a,b)=>a+b,0)/vals.length,peak=Math.max(...vals);document.getElementById('t-avg').innerHTML=avg.toFixed(2)+'<span class="m-unit">MB</span>';document.getElementById('t-peak').innerHTML=peak.toFixed(2)+'<span class="m-unit">MB</span>';}
    }
    renderErrs(d.recent_errors||[]);
  }catch(e){console.error(e)}
}

function renderErrs(errs){
  const el=document.getElementById('errs-full');if(!el)return;
  if(!errs.length){el.innerHTML='<div style="color:var(--green-t);padding:10px;font-size:12px;display:flex;align-items:center;gap:5px"><i class="ti ti-circle-check"></i> هیچ خطایی نیست</div>';return}
  el.innerHTML=errs.slice().reverse().map(e=>`<div class="erow"><div class="etime"><i class="ti ti-clock"></i>${new Date(e.time).toLocaleString('fa-IR')}</div><div class="emsg">${esc(e.error)}${e.url?' — '+esc(e.url):''}</div></div>`).join('');
}

function filterLinks(){
  const searchTerm = document.getElementById('link-search').value.toLowerCase();
  const statusFilter = document.getElementById('link-status-filter').value;
  const sortBy = document.getElementById('link-sort').value;
  
  let filtered = [...allLinks];
  
  // فیلتر جستجو
  if (searchTerm) {
    filtered = filtered.filter(l => 
      l.label.toLowerCase().includes(searchTerm) || 
      l.uuid.includes(searchTerm)
    );
  }
  
  // فیلتر وضعیت
  if (statusFilter !== 'all') {
    filtered = filtered.filter(l => {
      if (statusFilter === 'active') return l.active && !l.expired;
      if (statusFilter === 'expired') return l.expired;
      if (statusFilter === 'disabled') return !l.active;
      if (statusFilter === 'online') return onlineUuids.has(l.uuid);
      return true;
    });
  }
  
  // مرتب‌سازی
  switch(sortBy) {
    case 'oldest':
      filtered.sort((a,b) => new Date(a.created_at) - new Date(b.created_at));
      break;
    case 'name':
      filtered.sort((a,b) => a.label.localeCompare(b.label, 'fa'));
      break;
    case 'usage':
      filtered.sort((a,b) => b.used_bytes - a.used_bytes);
      break;
    case 'expiry':
      filtered.sort((a,b) => {
        const da = a.expires_at ? new Date(a.expires_at) : new Date('2100-01-01');
        const db = b.expires_at ? new Date(b.expires_at) : new Date('2100-01-01');
        return da - db;
      });
      break;
    default: // newest
      filtered.sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
  }
  
  renderLinksTable(filtered);
}

function renderLinksTable(links){
  const tb = document.getElementById('links-tb');
  const empty = document.getElementById('links-empty');
  document.getElementById('links-pg-cnt').textContent = toFa(links.length) + ' لینک';
  
  if (!links.length) {
    tb.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  
  tb.innerHTML = links.map(l => {
    const lim = l.limit_bytes === 0 ? '∞' : fmtB(l.limit_bytes);
    const pct = l.limit_bytes === 0 ? 0 : Math.min(100, l.used_bytes / l.limit_bytes * 100);
    const bc = pct > 90 ? 'var(--red)' : pct > 70 ? 'var(--amber)' : 'var(--accent)';
    const allowed = l.active && !l.expired;
    const onlineStatusHtml = onlineUuids.has(l.uuid) ? '<span class="online-dot"></span>' : '';
    
    return `<tr>
      <td><div class="ll">${esc(l.label)}</div><div class="lm"><span>${new Date(l.created_at).toLocaleDateString('fa-IR')}</span>${l.note ? `<span title="${esc(l.note)}"><i class="ti ti-note"></i>${esc(l.note.slice(0,25))}${l.note.length>25?'...':''}</span>` : ''}</div></td>
      <td style="text-align:center">${onlineStatusHtml}</td>
      <td><span class="uuid-chip" onclick="navigator.clipboard.writeText('${l.uuid}').then(()=>toast('UUID کپی شد','ok'))" title="کلیک برای کپی">${l.uuid.slice(0,13)}…</span></td>
      <td><div style="width:120px"><div class="ubar"><div class="ubar-f" style="width:${pct}%;background:${bc}"></div></div><div class="utxt">${fmtB(l.used_bytes)} / ${lim}</div></div></td>
      <td>${expChip(l.expires_at, l.expired)}</td>
      <td><button class="tog${allowed ? ' on' : ''}" onclick="toggleActive('${l.uuid}', ${!l.active})" title="${l.active ? 'غیرفعال کن' : 'فعال کن'}"></button></td>
      <td><div style="display:flex;gap:4px;flex-wrap:nowrap">
        <button class="btn btn-sm btn-g" onclick="navigator.clipboard.writeText('${esc(l.vless_link)}').then(()=>toast('لینک VLESS کپی شد','ok'))" title="کپی لینک"><i class="ti ti-copy"></i></button>
        <button class="btn btn-sm btn-g" onclick="navigator.clipboard.writeText('${esc(l.sub_url)}').then(()=>toast('لینک سابسکریپشن کپی شد','ok'))" title="کپی Sub URL"><i class="ti ti-rss"></i></button>
        <button class="btn btn-sm btn-g" onclick="window.open('https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent('${esc(l.vless_link)}'),'_blank')" title="QR"><i class="ti ti-qrcode"></i></button>
        <button class="btn btn-sm btn-g" onclick="resetUsage('${l.uuid}')" title="ریست مصرف"><i class="ti ti-rotate"></i></button>
        <button class="btn btn-sm btn-d" onclick="deleteLink('${l.uuid}')" title="حذف"><i class="ti ti-trash"></i></button>
      </div></td>
    </tr>`;
  }).join('');
}

function clearFilters(){
  document.getElementById('link-search').value = '';
  document.getElementById('link-status-filter').value = 'all';
  document.getElementById('link-sort').value = 'newest';
  filterLinks();
}

async function loadLinks(){
  try {
    const r = await authF('/api/links');
    const d = await r.json();
    allLinks = d.links || [];
    document.getElementById('links-nb').textContent = allLinks.length;
    document.getElementById('lsummary-badge').textContent = toFa(allLinks.length);
    filterLinks(); // نمایش با فیلترها
  } catch(e) { console.error(e); }
}

async function createLink(){
  const label=document.getElementById('nl-label').value.trim()||'لینک جدید',val=document.getElementById('nl-val').value,unit=document.getElementById('nl-unit').value,exp=document.getElementById('nl-exp').value,note=document.getElementById('nl-note').value.trim();
  try{
    const r=await authF('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,limit_value:val||0,limit_unit:unit,expires_days:exp||0,note})});
    if(!r.ok)throw new Error('failed');
    ['nl-label','nl-val','nl-exp','nl-note'].forEach(id=>document.getElementById(id).value='');
    toast('لینک ساخته شد','ok');loadLinks();
  }catch(e){toast('خطا در ساخت لینک','err')}
}

async function toggleActive(uuid,newState){
  try{const r=await authF('/api/links/'+uuid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:newState})});if(!r.ok)throw new Error();toast(newState?'لینک فعال شد':'لینک غیرفعال شد','ok');loadLinks();}catch(e){toast('خطا در تغییر وضعیت','err')}
}
async function resetUsage(uuid){
  try{const r=await authF('/api/links/'+uuid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});if(!r.ok)throw new Error();toast('مصرف ریست شد','ok');loadLinks();}catch(e){toast('خطا','err')}
}
async function deleteLink(uuid){
  if(!confirm('آیا از حذف این لینک مطمئن هستید؟'))return;
  try{const r=await authF('/api/links/'+uuid,{method:'DELETE'});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'failed')}toast('لینک حذف شد','ok');loadLinks();}catch(e){toast('خطا در حذف: '+e.message,'err')}
}

async function loadSubs(){
  document.getElementById('sub-all-url').textContent=location.protocol+'//'+location.host+'/sub-all';
  try{
    const r=await authF('/api/links'),d=await r.json();
    const links=(d.links||[]).filter(l=>l.active&&!l.expired);
    const el=document.getElementById('sub-list');
    if(!links.length){el.innerHTML='<div class="empty"><i class="ti ti-rss-off"></i><p>هیچ لینک فعالی نیست</p></div>';return}
    el.innerHTML=links.map(l=>`<div style="padding:12px 14px;background:var(--accent-d);border:1px solid var(--card-b);border-radius:9px;margin-bottom:7px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap"><div><div style="font-weight:600;font-size:12px;margin-bottom:3px">${esc(l.label)}</div><div class="sub-url">${esc(l.sub_url)}</div></div><div style="display:flex;gap:5px"><button class="btn btn-sm btn-g" onclick="navigator.clipboard.writeText('${esc(l.sub_url)}').then(()=>toast('کپی شد','ok'))"><i class="ti ti-copy"></i> کپی</button><button class="btn btn-sm btn-g" onclick="window.open('https://api.qrserver.com/v1/create-qr-code/?size=260x260&data='+encodeURIComponent('${esc(l.sub_url)}'),'_blank')"><i class="ti ti-qrcode"></i></button></div></div>`).join('');
  }catch(e){}
}
function cpSubAll(){navigator.clipboard.writeText(location.protocol+'//'+location.host+'/sub-all').then(()=>toast('آدرس سابسکریپشن کپی شد','ok'))}

async function loadConns(){
  try {
    const r = await authF('/api/connections');
    const d = await r.json();
    const users = d.users || [];
    document.getElementById('conns-live').innerHTML = `<span class="dot dg pulse"></span> ${users.length} کاربر`;
    const tbody = document.getElementById('conns-tbody');
    const empty = document.getElementById('conns-empty');
    if (users.length === 0) {
      tbody.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    let html = '';
    users.forEach(u => {
      html += `<tr>
        <td><strong>${esc(u.label)}</strong></td>
        <td style="text-align:center"><span class="badge bg-green"><span class="dot dg pulse"></span> آنلاین</span></td>
      </tr>`;
    });
    tbody.innerHTML = html;
  } catch(e) { console.error(e); }
}

async function loadErrs(){try{const r=await authF('/stats'),d=await r.json();renderErrs(d.recent_errors||[]);}catch(e){}}

async function fetchDefaultVless(){
  try{const r=await authF('/api/links'),d=await r.json();const links=d.links||[];const def=links.find(l=>l.limit_bytes===0&&l.active&&!l.expired)||links.find(l=>l.active&&!l.expired)||links[0];document.getElementById('vless-main').textContent=def?def.vless_link:'هنوز لینکی وجود ندارد — یک لینک بسازید';}catch(e){}
}
function cpText(id){navigator.clipboard.writeText(document.getElementById(id).textContent).then(()=>toast('کپی شد','ok'))}
function qrFor(id){const t=document.getElementById(id).textContent;window.open('https://api.qrserver.com/v1/create-qr-code/?size=280x280&data='+encodeURIComponent(t),'_blank')}
function refreshAll(){fetchStats();fetchDefaultVless();loadLinks();toast('در حال رفرش...','');if(document.getElementById('pg-subscriptions').classList.contains('on'))loadSubs()}

let ws;
function wsLog(c,m){const l=document.getElementById('ws-log'),p=document.createElement('p');const colors={ok:'#34D399',err:'#F87171',info:'#7BAED4',sent:'#FCD34D'};p.style.color=colors[c]||'#fff';p.textContent='['+new Date().toLocaleTimeString('fa-IR')+'] '+m;l.appendChild(p);l.scrollTop=l.scrollHeight}
function wsConn(){const u=document.getElementById('ws-uuid').value.trim();if(!u){toast('UUID یک لینک فعال را وارد کنید','err');return}const url=(location.protocol==='https:'?'wss':'ws')+'://'+location.host+'/ws/'+u;wsLog('info','اتصال: '+url);ws=new WebSocket(url);ws.onopen=()=>wsLog('ok','✓ متصل - UUID معتبر است');ws.onerror=()=>wsLog('err','✗ خطا - احتمالاً UUID نامعتبر یا غیرفعال');ws.onmessage=m=>wsLog('info','دریافت '+(m.data.size||m.data.length)+' byte');ws.onclose=e=>wsLog('err','قطع ('+e.code+')'+(e.code===1008?' - دسترسی رد شد':''))}
function wsSend(){const m=document.getElementById('ws-msg').value;if(!m||!ws||ws.readyState!==1)return;ws.send(m);wsLog('sent','ارسال: '+m);document.getElementById('ws-msg').value=''}
function wsDisc(){if(ws)ws.close()}

function initCharts(){
  const opts={responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{backgroundColor:'rgba(13,27,46,.95)',borderColor:'rgba(59,130,246,.2)',borderWidth:1,titleColor:'#E8F4FF',bodyColor:'#7BAED4',callbacks:{label:v=>`${v.parsed.y.toFixed(2)} MB`}}},scales:{x:{grid:{color:'rgba(59,130,246,.04)'},ticks:{color:'#3D6B8E',font:{size:9}}},y:{grid:{color:'rgba(59,130,246,.04)'},ticks:{color:'#3D6B8E',font:{size:9},callback:v=>v+'MB'}}}};
  const ds={label:'MB',data:[],borderColor:'rgba(59,130,246,.8)',backgroundColor:'rgba(59,130,246,.05)',fill:true,tension:.45,pointRadius:3,pointHoverRadius:5,borderWidth:2};
  ch1=new Chart(document.getElementById('ch1'),{type:'line',data:{labels:[],datasets:[{...ds}]},options:opts});
  ch3=new Chart(document.getElementById('ch3'),{type:'line',data:{labels:[],datasets:[{...ds}]},options:opts});
  ch2=new Chart(document.getElementById('ch2'),{type:'doughnut',data:{labels:['VLESS/WS','HTTP Proxy','سایر'],datasets:[{data:[70,25,5],backgroundColor:['rgba(59,130,246,.8)','rgba(16,185,129,.7)','rgba(139,92,246,.7)'],borderColor:'rgba(0,0,0,0)',borderWidth:3,hoverOffset:8}]},options:{responsive:true,maintainAspectRatio:false,cutout:'68%',plugins:{legend:{position:'bottom',labels:{color:'var(--t2)',font:{size:9},padding:10,usePointStyle:true}}}}});
}

document.addEventListener('DOMContentLoaded',async()=>{
  await checkAuth();
  initCharts();
  document.getElementById('set-host').textContent=location.host;
  document.getElementById('sub-all-url')&&(document.getElementById('sub-all-url').textContent=location.protocol+'//'+location.host+'/sub-all');
  updateOnlineStatus();
  fetchStats();fetchDefaultVless();loadLinks();
  setInterval(fetchStats,4000);
  setInterval(()=>{
    updateOnlineStatus();
    if(document.getElementById('pg-links').classList.contains('on'))loadLinks();
    if(document.getElementById('pg-subscriptions').classList.contains('on'))loadSubs();
    if(document.getElementById('pg-connections').classList.contains('on'))loadConns();
  },5000);
});
</script>
</body></html>"""

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
