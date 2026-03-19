import asyncio
import json
import time

from playwright.async_api import async_playwright


def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f}KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f}MB"


def _safe_json(obj):
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        return str(obj)


def _get_initiator(request):
    """Return (initiator_url, initiator_type) for a Playwright request."""
    initiator_url = None
    initiator_type = "other"
    try:
        init = request.initiator()
        if init:
            initiator_type = init.get("type", "other")
            initiator_url = init.get("url", "")
            if not initiator_url and init.get("stack"):
                frames = init["stack"].get("callFrames", [])
                if frames:
                    initiator_url = frames[0].get("url", "")
    except Exception:
        pass

    if not initiator_url:
        try:
            frame = request.frame
            if frame and frame.url and not frame.url.startswith("about:"):
                initiator_url = frame.url
                if initiator_type == "other":
                    initiator_type = "parser"
        except Exception:
            pass

    return initiator_url or None, initiator_type


async def analyze_url(url: str, send_callback):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    request_map: dict = {}
    req_counter = [0]
    first_request_time: list = [None]

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            executable_path=p.chromium.executable_path,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
            ],
        )
        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
        )
        page = await context.new_page()

        async def handle_request(request):
            req_counter[0] += 1
            req_id = str(req_counter[0])
            now = time.time() * 1000

            if first_request_time[0] is None:
                first_request_time[0] = now

            relative_start = now - first_request_time[0]

            initiator_url, initiator_type = _get_initiator(request)

            data = {
                "id": req_id,
                "url": request.url,
                "method": request.method,
                "type": request.resource_type,
                "headers": dict(request.headers),
                "start_time": now,
                "relative_start": relative_start,
                "initiator_url": initiator_url,
                "initiator_type": initiator_type,
                "status": None,
                "size": 0,
                "duration": None,
                "failed": False,
                "failure": None,
                "response_headers": {},
                "response_body": None,
            }
            request_map[request] = data

            await send_callback(
                {
                    "type": "request",
                    "data": {
                        "id": req_id,
                        "url": request.url,
                        "method": request.method,
                        "resourceType": request.resource_type,
                        "startTime": now,
                        "relativeStart": relative_start,
                        "initiatorUrl": initiator_url,
                        "initiatorType": initiator_type,
                    },
                }
            )

        async def handle_response(response):
            req = response.request
            if req not in request_map:
                return

            data = request_map[req]
            end_time = time.time() * 1000
            duration = round(end_time - data["start_time"], 2)

            try:
                body_bytes = await response.body()
                size = len(body_bytes)
            except Exception:
                size = 0

            response_body = None
            content_type = response.headers.get("content-type", "")
            if "json" in content_type:
                try:
                    response_body = await response.json()
                except Exception:
                    pass
            elif "text" in content_type:
                try:
                    text = await response.text()
                    response_body = text[:10_000]
                except Exception:
                    pass

            data.update(
                {
                    "status": response.status,
                    "size": size,
                    "duration": duration,
                    "response_headers": dict(response.headers),
                    "response_body": _safe_json(response_body),
                }
            )

            await send_callback(
                {
                    "type": "response",
                    "data": {
                        "id": data["id"],
                        "status": response.status,
                        "size": size,
                        "duration": duration,
                        "responseHeaders": dict(response.headers),
                    },
                }
            )

            # Send phase timing details for the main document
            if req.resource_type == "document" and response.status < 400:
                try:
                    t = req.timing  # playwright RequestTiming dict
                    dns_ms    = round(t["domainLookupEnd"] - t["domainLookupStart"], 1) if t.get("domainLookupEnd", -1) > 0 and t.get("domainLookupStart", -1) >= 0 else None
                    conn_ms   = round(t["connectEnd"] - t["connectStart"], 1)           if t.get("connectEnd", -1) > 0 and t.get("connectStart", -1) >= 0 else None
                    ssl_ms    = round(t["connectEnd"] - t["secureConnectionStart"], 1)  if t.get("secureConnectionStart", -1) > 0 else None
                    ttfb_ms   = round(t["responseStart"] - t["requestStart"], 1)        if t.get("responseStart", -1) > 0 and t.get("requestStart", -1) >= 0 else None
                    dl_ms     = round(t["responseEnd"] - t["responseStart"], 1)         if t.get("responseEnd", -1) > 0 and t.get("responseStart", -1) >= 0 else None

                    await send_callback({
                        "type": "phase_timing",
                        "data": {
                            "dns_ms":      dns_ms,
                            "connect_ms":  conn_ms,
                            "ssl_ms":      ssl_ms,
                            "ttfb_ms":     ttfb_ms,
                            "download_ms": dl_ms,
                            "doc_size":    size,
                            "doc_status":  response.status,
                            "doc_url":     req.url,
                            "doc_duration": duration,
                        },
                    })
                except Exception:
                    pass

        async def handle_request_failed(request):
            if request not in request_map:
                return
            data = request_map[request]
            data["failed"] = True
            data["failure"] = request.failure

            await send_callback(
                {
                    "type": "request_failed",
                    "data": {"id": data["id"], "failure": request.failure},
                }
            )

        page.on("request", lambda r: asyncio.ensure_future(handle_request(r)))
        page.on("response", lambda r: asyncio.ensure_future(handle_response(r)))
        page.on(
            "requestfailed",
            lambda r: asyncio.ensure_future(handle_request_failed(r)),
        )

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=60_000)
        except Exception as e:
            await send_callback(
                {"type": "navigate_error", "message": f"Navigation: {e}"}
            )

        await asyncio.sleep(1)

        # Capture browser-side performance timing
        try:
            timing = await page.evaluate('''() => {
                const t = window.performance.timing;
                const ns = t.navigationStart;
                return {
                    dom_interactive: t.domInteractive - ns,
                    dom_ready: t.domContentLoadedEventEnd - ns,
                    load_event: t.loadEventEnd - ns
                };
            }''')
            await send_callback({"type": "browser_timing", "data": timing})
        except Exception:
            pass

        all_requests = list(request_map.values())
        durations = [r["duration"] for r in all_requests if r.get("duration") is not None]
        total_size = sum(r.get("size") or 0 for r in all_requests)
        errors = sum(
            1
            for r in all_requests
            if r.get("failed") or (r.get("status") is not None and r["status"] >= 400)
        )

        summary = {
            "total_requests": len(all_requests),
            "total_size": _format_size(total_size),
            "total_size_bytes": total_size,
            "errors": errors,
            "slowest_request": round(max(durations), 2) if durations else 0,
            "avg_response_time": (
                round(sum(durations) / len(durations), 2) if durations else 0
            ),
        }

        tree: dict = {}
        for r in all_requests:
            try:
                from urllib.parse import urlparse
                host = urlparse(r["url"]).netloc or "unknown"
            except Exception:
                host = "unknown"
            tree.setdefault(host, {}).setdefault(r["type"], []).append(r["url"])

        await send_callback(
            {
                "type": "complete",
                "summary": summary,
                "tree": tree,
                "requests": all_requests,
            }
        )

        await browser.close()
