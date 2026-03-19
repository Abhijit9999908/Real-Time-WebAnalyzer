import asyncio
import json
import os
import urllib.request
import urllib.error

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from analyzer import analyze_url

app = FastAPI(title="Realtime Web Analyzer")


class ReplayPayload(BaseModel):
    url: str
    method: str = "GET"
    headers: dict = {}


@app.post("/replay")
async def replay_request(payload: ReplayPayload):
    """Replay an HTTP request and return status, headers, and body."""
    loop = asyncio.get_event_loop()

    def _do_request():
        method = payload.method.upper()
        safe_headers = {
            k: v for k, v in payload.headers.items()
            if k.lower() not in ("host", "content-length", "connection",
                                  "transfer-encoding", "te", "trailer",
                                  "upgrade", "proxy-authorization")
        }
        req = urllib.request.Request(payload.url, method=method, headers=safe_headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read(50_000)
                content_type = resp.headers.get("content-type", "")
                resp_headers = dict(resp.headers)
                status = resp.status

                if "json" in content_type:
                    try:
                        body = json.loads(raw.decode("utf-8", errors="replace"))
                    except Exception:
                        body = raw.decode("utf-8", errors="replace")[:5000]
                elif "text" in content_type:
                    body = raw.decode("utf-8", errors="replace")[:5000]
                else:
                    body = f"[binary — {len(raw)} bytes]"

                return {"status": status, "headers": resp_headers,
                        "body": body, "size": len(raw)}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "headers": dict(e.headers),
                    "body": e.reason, "size": 0, "error": str(e)}
        except Exception as ex:
            return {"status": 0, "headers": {}, "body": str(ex),
                    "size": 0, "error": str(ex)}

    result = await loop.run_in_executor(None, _do_request)
    return JSONResponse(result)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        raw = await websocket.receive_text()
        payload = json.loads(raw)
        url = payload.get("url", "").strip()

        if not url:
            await websocket.send_text(
                json.dumps({"type": "error", "message": "No URL provided"})
            )
            return

        async def send(event):
            try:
                await websocket.send_text(json.dumps(event, default=str))
            except Exception:
                pass

        await send({"type": "status", "message": f"Starting analysis of {url}…"})
        await analyze_url(url, send)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(
                json.dumps({"type": "error", "message": str(e)})
            )
        except Exception:
            pass


# Mount frontend static files — must come AFTER all API/WS routes
_frontend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
app.mount("/", StaticFiles(directory=_frontend_dir, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
