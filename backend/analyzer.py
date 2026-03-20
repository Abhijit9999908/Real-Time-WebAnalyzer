import asyncio
import json
import time
from urllib.parse import urlparse

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


def _safe_diff(t: dict, end_key: str, start_key: str):
    """Return end - start in ms if both are positive and end > start, else None."""
    end = t.get(end_key, -1)
    start = t.get(start_key, -1)
    if end > 0 and start >= 0 and end > start:
        return round(end - start, 1)
    return None


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


def _browser_duration(timing: dict, key_end: str = "responseStart") -> float | None:
    """Return (key_end - startTime) ms using browser-native timing, or None."""
    if not timing:
        return None
    start = timing.get("startTime", -1)
    end = timing.get(key_end, -1)
    if start >= 0 and end > 0 and end > start:
        return round(end - start, 2)
    return None


async def analyze_url(url: str, send_callback):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    request_map: dict = {}
    # Map req_id → (response, content_type, data, is_text) for deferred body reads
    response_body_queue: dict = {}
    req_counter = [0]
    first_req_wall_ms: list = [None]  # fallback wall-clock base for relative_start
    # Stores DNS/TCP/SSL/TTFB from the main document response timing
    doc_phase_timing: dict = {}

    # Media resource types/content patterns to skip body reading (potentially huge)
    _SKIP_BODY_TYPES = {"media"}
    _SKIP_BODY_CONTENT = ("video/", "audio/")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
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

            if first_req_wall_ms[0] is None:
                first_req_wall_ms[0] = now

            # Prefer browser-native timing (ms from navigation start) for accuracy.
            # request.timing["startTime"] is already relative to the document
            # navigation start — no subtraction needed.
            try:
                t = request.timing
                browser_start = t.get("startTime", -1) if t else -1
            except Exception:
                browser_start = -1

            if browser_start >= 0:
                relative_start = round(browser_start, 1)
            else:
                relative_start = round(now - first_req_wall_ms[0], 1)

            initiator_url, initiator_type = _get_initiator(request)

            data = {
                "id": req_id,
                "url": request.url,
                "method": request.method,
                "type": request.resource_type,
                "headers": dict(request.headers),
                "start_time": now,        # Python wall-clock fallback
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

            # ── Duration: use browser-native timing (responseStart - startTime).
            # This is "time to first byte" for this resource — accurate and
            # free of Python event-loop scheduling jitter.
            # The final duration (responseEnd - startTime) is computed after
            # body download in the deferred body-read loop.
            try:
                t = req.timing
                duration = _browser_duration(t, "responseStart")
            except Exception:
                duration = None

            if duration is None:
                # Fallback: wall-clock difference (less accurate)
                duration = round(time.time() * 1000 - data["start_time"], 2)

            content_type = response.headers.get("content-type", "")
            is_text = "text" in content_type or "json" in content_type

            # Use content-length for immediate size display (updated after body read)
            cl = response.headers.get("content-length", "")
            size = int(cl) if cl.isdigit() else 0

            # Queue for deferred body read if:
            #   • text/JSON (need content + accurate size), OR
            #   • size unknown (no content-length) AND not a huge media resource
            resource_type = req.resource_type
            is_media = resource_type in _SKIP_BODY_TYPES or any(
                m in content_type for m in _SKIP_BODY_CONTENT
            )
            if is_text or (not is_media and size == 0):
                response_body_queue[data["id"]] = (response, content_type, data, is_text)

            data.update(
                {
                    "status": response.status,
                    "size": size,
                    "duration": duration,
                    "response_headers": dict(response.headers),
                }
            )

            # Send response event immediately — body/final timing updated later
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

            # Extract phase timings from the main document only
            if req.resource_type == "document" and response.status < 400:
                try:
                    t = req.timing

                    dns_ms = _safe_diff(t, "domainLookupEnd", "domainLookupStart")

                    # TCP: socket establishment only — exclude TLS for HTTPS
                    sec_start = t.get("secureConnectionStart", -1)
                    if sec_start > 0:
                        # HTTPS: TCP handshake ends when TLS begins
                        tcp_ms = _safe_diff(t, "secureConnectionStart", "connectStart")
                    else:
                        # HTTP or reused connection
                        tcp_ms = _safe_diff(t, "connectEnd", "connectStart")

                    # SSL: TLS handshake only (secureConnectionStart → connectEnd)
                    conn_end = t.get("connectEnd", -1)
                    ssl_ms = (
                        round(conn_end - sec_start, 1)
                        if sec_start > 0 and conn_end > sec_start
                        else None
                    )

                    ttfb_ms = _safe_diff(t, "responseStart", "requestStart")
                    dl_ms   = _safe_diff(t, "responseEnd", "responseStart")

                    # Persist for later server_time computation
                    doc_phase_timing.update(
                        {
                            "dns_ms":  dns_ms  or 0,
                            "tcp_ms":  tcp_ms  or 0,
                            "ssl_ms":  ssl_ms  or 0,
                            "ttfb_ms": ttfb_ms or 0,
                        }
                    )

                    await send_callback(
                        {
                            "type": "phase_timing",
                            "data": {
                                "dns_ms":       dns_ms,
                                "connect_ms":   tcp_ms,
                                "ssl_ms":       ssl_ms,
                                "ttfb_ms":      ttfb_ms,
                                "download_ms":  dl_ms,
                                "doc_size":     size,
                                "doc_status":   response.status,
                                "doc_url":      req.url,
                                "doc_duration": duration,
                            },
                        }
                    )
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

        # Wait for the full load event so loadEventEnd is available in Navigation Timing.
        try:
            await page.wait_for_load_state("load", timeout=20_000)
        except Exception:
            pass

        # Brief buffer for late-fired async resource events
        await asyncio.sleep(0.3)

        # ── Deferred body reads ──────────────────────────────────────────
        # Reads response bodies now that the page is fully loaded.
        # Also updates size and duration with browser-native responseEnd timing.
        for req_id, (response, content_type, data, read_content) in list(
            response_body_queue.items()
        ):
            try:
                body_bytes = await response.body()

                # Accurate size from actual decoded bytes
                data["size"] = len(body_bytes)

                # Final duration: responseEnd - startTime (browser-native, most accurate)
                try:
                    t = response.request.timing
                    final_dur = _browser_duration(t, "responseEnd")
                    if final_dur is not None:
                        data["duration"] = final_dur
                except Exception:
                    pass

                if read_content:
                    if "json" in content_type:
                        try:
                            data["response_body"] = _safe_json(
                                json.loads(body_bytes.decode("utf-8", errors="replace"))
                            )
                        except Exception:
                            data["response_body"] = body_bytes.decode(
                                "utf-8", errors="replace"
                            )[:10_000]
                    else:
                        data["response_body"] = body_bytes.decode(
                            "utf-8", errors="replace"
                        )[:10_000]
            except Exception:
                pass
        response_body_queue.clear()

        # ── Browser-side Navigation Timing ──────────────────────────────
        try:
            timing = await page.evaluate(
                """() => {
                const nav = performance.getEntriesByType('navigation')[0];
                const t   = window.performance.timing;
                const ns  = t.navigationStart;

                // Prefer Level 2 (PerformanceNavigationTiming) relative-to-origin ms;
                // fall back to Level 1 (performance.timing) subtracting navigationStart.
                function g(navKey, legacyKey) {
                    if (nav && nav[navKey] != null && nav[navKey] > 0)
                        return Math.max(0, Math.round(nav[navKey]));
                    const v = t[legacyKey];
                    return (v && v > 0) ? Math.max(0, Math.round(v - ns)) : 0;
                }

                return {
                    dom_interactive: g('domInteractive',           'domInteractive'),
                    dom_ready:       g('domContentLoadedEventEnd', 'domContentLoadedEventEnd'),
                    load_event:      g('loadEventEnd',             'loadEventEnd'),
                    response_start:  g('responseStart',            'responseStart'),
                    response_end:    g('responseEnd',              'responseEnd'),
                };
            }"""
            )
            await send_callback({"type": "browser_timing", "data": timing})

            # ── Compute server_time and client_time ─────────────────────
            dns_ms  = doc_phase_timing.get("dns_ms")  or 0.0
            tcp_ms  = doc_phase_timing.get("tcp_ms")  or 0.0
            ssl_ms  = doc_phase_timing.get("ssl_ms")  or 0.0
            ttfb_ms = doc_phase_timing.get("ttfb_ms") or 0.0

            resp_start = float(timing.get("response_start") or 0)
            resp_end   = float(timing.get("response_end")   or 0)
            load_end   = float(timing.get("load_event")     or 0)

            # download_ms: time from first byte to last byte of main document
            if resp_end > 0 and resp_start > 0 and resp_end > resp_start:
                download_ms = round(resp_end - resp_start, 1)
            else:
                download_ms = 0.0

            # render_ms: time from HTML body received to load event (CSS/JS/render)
            if load_end > 0 and resp_end > 0 and load_end > resp_end:
                render_ms = round(load_end - resp_end, 1)
            elif load_end > 0:
                render_ms = round(load_end, 1)
            else:
                render_ms = 0.0

            # server_time: DNS + TCP (no TLS) + TLS + TTFB — no double-counting
            server_time = round(dns_ms + tcp_ms + ssl_ms + ttfb_ms, 1)
            client_time = round(download_ms + render_ms, 1)

            await send_callback(
                {
                    "type": "performance",
                    "data": {
                        "server_time": server_time,
                        "client_time": client_time,
                        "dns":      round(dns_ms,  1),
                        "tcp":      round(tcp_ms,  1),
                        "ssl":      round(ssl_ms,  1),
                        "ttfb":     round(ttfb_ms, 1),
                        "download": download_ms,
                        "render":   render_ms,
                    },
                }
            )
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

        # Free request objects to avoid memory leaks
        request_map.clear()

        await browser.close()
