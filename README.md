# Realtime Web Analyzer

A lightweight browser-based tool that loads any URL in a headless Chromium instance, captures all network activity in real time, and displays it in a clean dark-themed dashboard — like a simplified Chrome DevTools Network tab.

## Features

- Real-time request/response streaming via WebSocket
- Request table with method, URL, type, status, size, and timing
- Color-coded status codes and resource types
- Details panel with full headers and response body
- Timeline visualization (Chrome DevTools style)
- Resource tree grouped by domain
- Filter by resource type (JS, CSS, Images, XHR…)
- Export full analysis as JSON
- Replay any captured request

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
playwright install chromium
```

### 2. Run the server

```bash
cd backend
python app.py
```

### 3. Open the app

Navigate to **http://localhost:8000** in your browser, paste any URL, and click **Analyze**.

## Project Structure

```
realtime-web-analyzer/
├── frontend/
│   ├── index.html      # UI shell
│   ├── style.css       # Dark theme styles
│   └── app.js          # WebSocket client + rendering
├── backend/
│   ├── app.py          # FastAPI server + WebSocket endpoint
│   └── analyzer.py     # Playwright network capture logic
├── requirements.txt
├── render.yaml         # Render.com deployment config
└── .gitignore
```

## Requirements

- Python 3.10+
- Chromium (installed via `playwright install chromium`)
# Real-Time-WebAnalyzer
