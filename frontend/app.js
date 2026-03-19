/* ═══════════════════════════════════════════════════════════════════════
   Realtime Web Analyzer — app.js
   Pipeline journey visualization, real-time WebSocket driven
   Features: Live Network Table, Waterfall, Dependency Graph, Details Panel
   ═══════════════════════════════════════════════════════════════════════ */

// ── DOM helpers ────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Analyze button HTML snapshot (restored after analysis) ─────────────
const ANALYZE_BTN_HTML = document.getElementById('analyze-btn').innerHTML;

// ── Stage definitions ──────────────────────────────────────────────────
const STAGES = {
  dns:    { id: 'st-dns',    timingId: 't-dns',    connNext: 'c-dns-tcp' },
  tcp:    { id: 'st-tcp',    timingId: 't-tcp',    connNext: 'c-tcp-tls',  connPrev: 'c-dns-tcp' },
  tls:    { id: 'st-tls',    timingId: 't-tls',    connNext: 'c-tls-http', connPrev: 'c-tcp-tls' },
  http:   { id: 'st-http',   timingId: 't-http',   connNext: 'c-http-srv', connPrev: 'c-tls-http' },
  server: { id: 'st-server', timingId: 't-server', connNext: 'mid',        connPrev: 'c-http-srv' },
  html:   { id: 'st-html',   timingId: 't-html',   connNext: 'c-html-parse', connPrev: 'mid' },
  parse:  { id: 'st-parse',  timingId: 't-parse',  connNext: 'c-parse-cssjs', connPrev: 'c-html-parse' },
  cssjs:  { id: 'st-cssjs',  timingId: 't-cssjs',  connNext: 'c-cssjs-dom',   connPrev: 'c-parse-cssjs' },
  dom:    { id: 'st-dom',    timingId: 't-dom',    connNext: 'c-dom-load',    connPrev: 'c-cssjs-dom' },
  load:   { id: 'st-load',   timingId: 't-load',   connPrev: 'c-dom-load' },
};

// ── State ──────────────────────────────────────────────────────────────
const state = {
  ws: null,
  analyzing: false,
  requests: new Map(),      // id → request object
  phaseTiming: null,
  browserTiming: null,
  exportData: null,
  selectedReqId: null,
};

// ── Stage helpers ──────────────────────────────────────────────────────
function setStageState(key, newState, timingText) {
  const def = STAGES[key];
  if (!def) return;
  const el = $(def.id);
  if (!el) return;
  el.classList.remove('is-pending', 'is-active', 'is-done', 'is-error');
  el.classList.add(`is-${newState}`);
  if (timingText != null) {
    const te = $(def.timingId);
    if (te) te.textContent = timingText;
  }
  if (newState === 'active' || newState === 'done') {
    if (def.connPrev) {
      const connEl = def.connPrev === 'mid' ? $('mid-connector') : $(def.connPrev);
      if (connEl) connEl.classList.add('is-active');
    }
    if (newState === 'active' && def.connNext) {
      const connEl = def.connNext === 'mid' ? $('mid-connector') : $(def.connNext);
      if (connEl) connEl.classList.add('is-active');
    }
  }
}

function setPending(key) { setStageState(key, 'pending', null); }
function setActive(key, ms)  { setStageState(key, 'active', ms != null ? `${ms}ms` : null); }
function setDone(key, ms)    { setStageState(key, 'done', ms != null ? `${ms}ms` : null); }

const STAGE_ORDER = ['dns','tcp','tls','http','server','html','parse','cssjs','dom','load'];

function resetAllStages() {
  STAGE_ORDER.forEach(key => {
    const def = STAGES[key];
    const el = $(def.id);
    if (el) el.classList.remove('is-pending','is-active','is-done','is-error');
    const te = $(def.timingId);
    if (te) te.textContent = '';
  });
  ['c-dns-tcp','c-tcp-tls','c-tls-http','c-http-srv',
   'c-html-parse','c-parse-cssjs','c-cssjs-dom','c-dom-load',
   'mid-connector'].forEach(id => {
    const el = $(id);
    if (el) el.classList.remove('is-active');
  });
}

function pendingAllStages() {
  STAGE_ORDER.forEach((key, i) => {
    setTimeout(() => setPending(key), i * 80);
  });
}

// ── Status helpers ─────────────────────────────────────────────────────
function setStatus(type, text) {
  const ind = $('status-indicator');
  const txt = $('status-text');
  if (ind) ind.className = `indicator-${type}`;
  if (txt) txt.textContent = text;
}

function setProgress(pct) {
  const el = $('progress-fill');
  if (el) el.style.width = pct + '%';
}

// ── Metrics ────────────────────────────────────────────────────────────
function setMetricVal(id, text) {
  const el = $(id);
  if (!el || el.textContent === text) return;
  const wasDash = el.textContent === '—';
  el.classList.remove('metric-loading', 'metric-pop');
  el.textContent = text;
  if (wasDash && text !== '—') {
    void el.offsetWidth; // trigger reflow so animation restarts
    el.classList.add('metric-pop');
    el.addEventListener('animationend', () => el.classList.remove('metric-pop'), { once: true });
  }
}

function updateMetrics() {
  const pt = state.phaseTiming;
  const bt = state.browserTiming;
  const reqs = [...state.requests.values()];
  const totalSize = reqs.reduce((s,r) => s + (r.size || 0), 0);

  setMetricVal('v-reqs', reqs.length ? String(reqs.length) : '—');
  setMetricVal('v-size', totalSize ? formatSize(totalSize) : '—');
  if (pt) {
    if (pt.dns_ms  != null) setMetricVal('v-dns',  `${pt.dns_ms}ms`);
    if (pt.ttfb_ms != null) setMetricVal('v-ttfb', `${pt.ttfb_ms}ms`);
  }
  if (bt) {
    if (bt.dom_ready  != null) setMetricVal('v-dom',  `${bt.dom_ready}ms`);
    if (bt.load_event != null) setMetricVal('v-load', `${bt.load_event}ms`);
  }

  $('tab-req-count').textContent = reqs.length;
}

// ── Format helpers ─────────────────────────────────────────────────────
function formatSize(bytes) {
  if (!bytes) return '—';
  if (bytes < 1024)        return `${bytes}B`;
  if (bytes < 1024*1024)   return `${(bytes/1024).toFixed(1)}KB`;
  return `${(bytes/1024/1024).toFixed(1)}MB`;
}

function shortUrl(url, maxLen = 60) {
  try {
    const u = new URL(url);
    const path = u.pathname + u.search;
    const host = u.host;
    const full = host + path;
    return full.length > maxLen ? full.slice(0, maxLen) + '…' : full;
  } catch {
    return url.length > maxLen ? url.slice(0, maxLen) + '…' : url;
  }
}

function fileName(url) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split('/').filter(Boolean);
    return parts[parts.length - 1] || u.hostname;
  } catch {
    return url.split('/').pop() || url;
  }
}

function statusClass(status, failed) {
  if (failed) return 'status-failed';
  if (!status) return 'status-pending';
  if (status < 200) return 'status-1xx';
  if (status < 300) return 'status-2xx';
  if (status < 400) return 'status-3xx';
  if (status < 500) return 'status-4xx';
  return 'status-5xx';
}

function methodClass(method) {
  const m = (method || '').toUpperCase();
  return ['GET','POST','PUT','DELETE','PATCH'].includes(m) ? `method-${m}` : 'method-other';
}

function typeClass(type) {
  const t = (type || '').toLowerCase();
  if (t === 'xhr') return 'type-fetch';
  return `type-${t}`;
}

function typeLabel(type) {
  const map = { document:'HTML', stylesheet:'CSS', script:'JS',
                image:'IMG', font:'FONT', fetch:'XHR', xhr:'XHR',
                media:'MED', other:'—' };
  return map[(type||'').toLowerCase()] || type || '—';
}

// ── Resource Breakdown Bar ─────────────────────────────────────────────
const TYPE_COLORS = {
  document:'#3b82f6', stylesheet:'#22c55e', script:'#a855f7',
  image:'#f59e0b', font:'#ec4899', fetch:'#06b6d4', xhr:'#06b6d4',
  media:'#94a3b8', other:'#4b6080',
};
const TYPE_LABELS = {
  document:'HTML', stylesheet:'CSS', script:'JS',
  image:'Images', font:'Fonts', fetch:'Fetch/XHR', xhr:'Fetch/XHR',
  media:'Media', other:'Other',
};

function renderResourceBar(requests) {
  const sec = $('resource-section');
  const bar = $('resource-bar');
  const legend = $('resource-legend');
  if (!sec || !bar || !legend) return;
  const byType = {};
  requests.forEach(r => {
    const t = (r.type || 'other').toLowerCase();
    const key = (t === 'xhr') ? 'fetch' : t;
    if (!byType[key]) byType[key] = { count: 0, size: 0 };
    byType[key].count++;
    byType[key].size += r.size || 0;
  });
  const totalSize = Object.values(byType).reduce((s,v) => s + v.size, 0);
  const totalCount = requests.length;
  $('res-total-label').textContent = `${totalCount} requests · ${formatSize(totalSize)}`;
  const sorted = Object.entries(byType)
    .filter(([,v]) => v.size > 0 || v.count > 0)
    .sort((a,b) => b[1].size - a[1].size);
  bar.innerHTML = sorted.map(([type, data]) => {
    const pct = totalSize > 0 ? (data.size / totalSize * 100) : (data.count / totalCount * 100);
    const color = TYPE_COLORS[type] || TYPE_COLORS.other;
    return `<div class="res-segment" style="width:0%;background:${color}" data-pct="${pct.toFixed(2)}"></div>`;
  }).join('');
  legend.innerHTML = sorted.map(([type, data]) => {
    const color = TYPE_COLORS[type] || TYPE_COLORS.other;
    const label = TYPE_LABELS[type] || type;
    return `<div class="res-legend-item">
      <span class="res-legend-dot" style="background:${color}"></span>
      <span>${label}</span>
      <span class="res-legend-val">${formatSize(data.size)} (${data.count})</span>
    </div>`;
  }).join('');
  sec.classList.remove('hidden');
  requestAnimationFrame(() => {
    bar.querySelectorAll('.res-segment').forEach(seg => {
      seg.style.width = seg.dataset.pct + '%';
    });
  });
}

// ── Tab System ─────────────────────────────────────────────────────────
document.querySelectorAll('.dev-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll('.dev-tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.dev-tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    $(`tab-${tab}`).classList.add('active');
    if (tab === 'waterfall') renderWaterfall();
    if (tab === 'dependency') renderDependencyGraph();
  });
});

// ── Network Request Table ──────────────────────────────────────────────
function addTableRow(req) {
  const tbody = $('req-table-body');
  if (!tbody) return;

  // Remove empty placeholder
  const empty = tbody.querySelector('.req-table-empty');
  if (empty) empty.remove();

  const tr = document.createElement('tr');
  tr.id = `tr-${req.id}`;
  tr.className = 'req-new';
  tr.dataset.id = req.id;
  tr.innerHTML = buildRowHtml(req);
  tr.addEventListener('click', () => openDetails(req.id));
  tbody.appendChild(tr);
}

function updateTableRow(id) {
  const req = state.requests.get(id);
  if (!req) return;
  const tr = $(`tr-${id}`);
  if (!tr) return;
  tr.innerHTML = buildRowHtml(req);
  tr.addEventListener('click', () => openDetails(id));

  // Error row highlighting
  tr.className = '';
  if (req.failed) tr.classList.add('req-row-failed');
  else if (req.status && req.status >= 500) tr.classList.add('req-row-5xx');
  else if (req.status && req.status >= 400) tr.classList.add('req-row-4xx');
  if (state.selectedReqId === id) tr.classList.add('selected');
}

function buildRowHtml(req) {
  const statusBadge = req.failed
    ? `<span class="status-badge status-failed">FAIL</span>`
    : req.status
      ? `<span class="status-badge ${statusClass(req.status, false)}">${req.status}</span>`
      : `<span class="status-badge status-pending">···</span>`;
  const type = (req.type || 'other').toLowerCase();
  const typeColor = TYPE_COLORS[type === 'xhr' ? 'fetch' : type] || TYPE_COLORS.other;
  const typePill = `<span class="type-pill dep-type-badge ${typeClass(req.type)}">${typeLabel(req.type)}</span>`;
  return `
    <td style="color:var(--muted);font-size:10px;">${req.id}</td>
    <td><span class="method-badge ${methodClass(req.method)}">${req.method || 'GET'}</span></td>
    <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;color:var(--text);" title="${req.url}">${shortUrl(req.url)}</td>
    <td>${statusBadge}</td>
    <td>${typePill}</td>
    <td style="color:var(--muted);">${req.size ? formatSize(req.size) : '—'}</td>
    <td style="color:${req.duration > 1000 ? 'var(--red)' : req.duration > 300 ? 'var(--amber)' : 'var(--green)'};">${req.duration != null ? req.duration + 'ms' : '—'}</td>
  `;
}

// ── Waterfall ──────────────────────────────────────────────────────────
function renderWaterfall() {
  const container = $('waterfall-rows');
  const emptyEl   = $('waterfall-empty');
  const headerEl  = $('wf-timeline-header');
  if (!container) return;

  const reqs = [...state.requests.values()];
  if (!reqs.length) {
    container.innerHTML = '';
    if (emptyEl) emptyEl.style.display = 'block';
    return;
  }
  if (emptyEl) emptyEl.style.display = 'none';

  // Calculate total time span
  const starts = reqs.map(r => r.relative_start || r.relativeStart || 0);
  const ends   = reqs.map(r => {
    const s = r.relative_start || r.relativeStart || 0;
    return s + (r.duration || 0);
  });
  const maxMs = Math.max(...ends, 1);

  // Build timeline ticks
  const ticks = 5;
  headerEl.innerHTML = '';
  for (let i = 0; i <= ticks; i++) {
    const pct = (i / ticks) * 100;
    const ms  = Math.round((i / ticks) * maxMs);
    const tick = document.createElement('span');
    tick.className = 'wf-tick';
    tick.style.left = pct + '%';
    tick.textContent = ms + 'ms';
    headerEl.appendChild(tick);
  }

  // Render rows
  container.innerHTML = reqs.map(req => {
    const start   = req.relative_start || req.relativeStart || 0;
    const dur     = req.duration || 0;
    const leftPct = (start / maxMs) * 100;
    const widPct  = Math.max((dur / maxMs) * 100, 0.3);
    const type    = (req.type || 'other').toLowerCase();
    const color   = TYPE_COLORS[type === 'xhr' ? 'fetch' : type] || TYPE_COLORS.other;
    const name    = fileName(req.url);
    const sClass  = statusClass(req.status, req.failed);
    const statusText = req.failed ? 'FAIL' : (req.status || '…');
    const typePill = `<span class="dep-type-badge ${typeClass(req.type)}" style="font-size:9px;padding:0 4px;">${typeLabel(req.type)}</span>`;

    return `<div class="wf-row" data-id="${req.id}">
      <div class="wf-label">
        ${typePill}
        <span class="wf-name" title="${req.url}">${name}</span>
      </div>
      <div class="wf-timeline">
        <div class="wf-bar-track">
          <div class="wf-bar" style="left:${leftPct.toFixed(2)}%;width:${widPct.toFixed(2)}%;background:${color};opacity:${req.status && req.status >= 400 ? 0.5 : 0.85};"
               title="${dur}ms"></div>
          ${dur > 0 ? `<span class="wf-bar-label" style="left:calc(${(leftPct + widPct).toFixed(2)}% + 4px)">${dur}ms</span>` : ''}
        </div>
      </div>
    </div>`;
  }).join('');

  // Click handlers
  container.querySelectorAll('.wf-row').forEach(row => {
    row.addEventListener('click', () => openDetails(row.dataset.id));
  });
}

// ── Dependency Graph ───────────────────────────────────────────────────

function buildDepTree(requests) {
  // Map url → request (use first seen for each url)
  const urlToReq = new Map();
  requests.forEach(r => { if (!urlToReq.has(r.url)) urlToReq.set(r.url, r); });

  // Children map: parent_url → [child requests]
  const children = new Map();
  const childSet = new Set(); // all child request ids

  requests.forEach(r => {
    const parent = r.initiator_url;
    if (parent && parent !== r.url) {
      if (!children.has(parent)) children.set(parent, []);
      children.get(parent).push(r);
      childSet.add(r.id);
    }
  });

  // Roots: requests not appearing as children of something
  const roots = requests.filter(r => !childSet.has(r.id));

  return { roots, children };
}

function getMaxDepth(nodes, children, depth) {
  if (!nodes.length) return depth;
  let max = depth;
  nodes.forEach(node => {
    const childList = children.get(node.url) || [];
    if (childList.length) {
      const d = getMaxDepth(childList, children, depth + 1);
      if (d > max) max = d;
    }
  });
  return max;
}

// Build colored connector HTML from prefix string + connector type
function buildConnHtml(prefix, connType) {
  let html = '';
  // prefix is built from 3-char chunks: '│  ' or '   '
  for (let i = 0; i < prefix.length; i += 3) {
    const ch = prefix[i];
    if (ch === '│') {
      html += `<span class="tree-vert">│</span><span class="tree-spc">  </span>`;
    } else {
      html += `<span class="tree-spc">   </span>`;
    }
  }
  if (connType === 'branch') html += `<span class="tree-branch">├─ </span>`;
  else if (connType === 'last') html += `<span class="tree-last">└─ </span>`;
  return html;
}

function renderDependencyGraph() {
  const container = $('dep-tree');
  const statsEl   = $('dep-stats');
  if (!container) return;

  const reqs = [...state.requests.values()];
  if (!reqs.length) {
    container.innerHTML = '<div class="dep-empty">Run an analysis to see the dependency graph…</div>';
    if (statsEl) statsEl.innerHTML = '';
    return;
  }

  const { roots, children } = buildDepTree(reqs);

  // Stats
  const origins   = new Set(reqs.map(r => { try { return new URL(r.url).hostname; } catch { return '?'; } })).size;
  const maxDepth  = getMaxDepth(roots, children, 0);
  const errorCnt  = reqs.filter(r => r.failed || (r.status && r.status >= 400)).length;

  if (statsEl) {
    statsEl.innerHTML = `
      <span class="dep-stat-item"><span class="dep-stat-val">${reqs.length}</span> resources</span>
      <span class="dep-stat-sep">·</span>
      <span class="dep-stat-item"><span class="dep-stat-val">${origins}</span> ${origins === 1 ? 'origin' : 'origins'}</span>
      <span class="dep-stat-sep">·</span>
      <span class="dep-stat-item"><span class="dep-stat-val">${maxDepth}</span> levels deep</span>
      ${errorCnt ? `<span class="dep-stat-sep">·</span><span class="dep-stat-item dep-stat-error"><span class="dep-stat-val">${errorCnt}</span> errors</span>` : ''}
    `;
  }

  container.innerHTML = '';
  renderDepNodes(container, roots, children, '', true);
}

function renderDepNodes(container, nodes, children, prefix, isRoot) {
  nodes.forEach((req, idx) => {
    const isLast     = idx === nodes.length - 1;
    const connType   = isRoot ? 'root' : (isLast ? 'last' : 'branch');
    // 3-char prefix chunks so tree-vert/tree-spc line up
    const childPfx   = isRoot ? '' : (isLast ? '   ' : '│  ');

    const childList  = children.get(req.url) || [];
    const hasChildren = childList.length > 0;

    const nodeEl = document.createElement('div');
    nodeEl.className = 'dep-node dep-node-entry';

    const isError    = req.failed || (req.status && req.status >= 400);
    const isCritical = req.status && req.status >= 500;
    const dotClass   = req.failed ? 'error'
      : !req.status   ? 'pending'
      : req.status >= 400 ? 'error'
      : req.status >= 300 ? 'warn'
      : 'ok';

    const row = document.createElement('div');
    row.className = `dep-node-row${isError ? ' dep-row-error' : ''}${isCritical ? ' dep-row-critical' : ''}`;
    row.dataset.id = req.id;

    const connHtml   = isRoot ? '' : buildConnHtml(prefix, connType);
    const typeCls    = typeClass(req.type);
    const typeLbl    = typeLabel(req.type);
    const urlShort   = shortUrl(req.url, 52);
    const sizeStr    = req.size ? formatSize(req.size) : '';
    const durStr     = req.duration != null ? `${req.duration}ms` : '';
    const statusStr  = req.failed ? '✗' : req.status ? `${req.status}` : '···';
    const statusColor = req.failed || (req.status && req.status >= 400) ? 'var(--red)'
      : req.status && req.status >= 300 ? 'var(--amber)'
      : req.status ? 'var(--green)'
      : 'var(--muted)';

    row.innerHTML = `
      <span class="dep-conn">${connHtml}</span>
      <div class="dep-node-inner">
        ${hasChildren
          ? `<button class="dep-toggle" data-expanded="true">−</button>`
          : `<span class="dep-toggle-spacer"></span>`}
        <span class="dep-type-badge ${typeCls}">${typeLbl}</span>
        <span class="dep-node-url" title="${req.url}">${urlShort}</span>
        <span class="dep-node-meta">
          ${sizeStr ? `<span class="dep-node-size">${sizeStr}</span>` : ''}
          ${durStr  ? `<span class="dep-node-dur">${durStr}</span>`   : ''}
          <span class="dep-node-status" style="color:${statusColor};font-size:10px;font-family:var(--mono);">${statusStr}</span>
          <span class="dep-status-dot ${dotClass}"></span>
        </span>
      </div>
    `;

    row.addEventListener('click', (e) => {
      if (e.target.closest('.dep-toggle')) return;
      openDetails(req.id);
    });

    nodeEl.appendChild(row);

    if (hasChildren) {
      const childContainer = document.createElement('div');
      childContainer.className = 'dep-children';
      renderDepNodes(childContainer, childList, children, prefix + childPfx, false);
      nodeEl.appendChild(childContainer);

      const toggle = row.querySelector('.dep-toggle');
      if (toggle) {
        toggle.addEventListener('click', (e) => {
          e.stopPropagation();
          const expanded = toggle.dataset.expanded === 'true';
          toggle.dataset.expanded = String(!expanded);
          toggle.textContent = expanded ? '+' : '−';
          childContainer.classList.toggle('collapsed', expanded);
        });
      }
    }

    container.appendChild(nodeEl);
  });
}

// ── Request Details Panel ──────────────────────────────────────────────
function openDetails(id) {
  const req = state.requests.get(String(id));
  if (!req) return;

  state.selectedReqId = String(id);

  // Highlight selected row
  document.querySelectorAll('.req-table tbody tr').forEach(tr => tr.classList.remove('selected'));
  document.querySelectorAll('.wf-row').forEach(r => r.classList.remove('selected'));
  const tr = $(`tr-${id}`);
  if (tr) tr.classList.add('selected');
  const wfRow = document.querySelector(`.wf-row[data-id="${id}"]`);
  if (wfRow) wfRow.classList.add('selected');

  // Populate header
  const method = req.method || 'GET';
  const methodBadge = $('details-method-badge');
  methodBadge.textContent = method;
  methodBadge.className = `details-method method-badge ${methodClass(method)}`;

  $('details-title').textContent = req.url;
  $('details-title').title = req.url;

  const statusBadge = $('details-status-badge');
  statusBadge.textContent = req.failed ? 'FAILED' : (req.status || 'Pending');
  statusBadge.className = `status-badge ${statusClass(req.status, req.failed)}`;

  const typeEl = $('details-type-badge');
  typeEl.textContent = typeLabel(req.type);
  typeEl.className = `details-type dep-type-badge ${typeClass(req.type)}`;

  $('details-size-badge').textContent = req.size ? formatSize(req.size) : '—';
  $('details-dur-badge').textContent  = req.duration != null ? req.duration + 'ms' : '—';

  // Timing grid
  const timingEl = $('details-timing');
  const dur = req.duration;
  const durCls = !dur ? '' : dur > 1000 ? 'slow' : dur > 300 ? 'med' : 'fast';
  timingEl.innerHTML = `
    <div class="timing-item">
      <span class="timing-label">Duration</span>
      <span class="timing-val ${durCls}">${dur != null ? dur + 'ms' : '—'}</span>
    </div>
    <div class="timing-item">
      <span class="timing-label">Start (rel)</span>
      <span class="timing-val">${req.relative_start != null ? Math.round(req.relative_start) + 'ms' : '—'}</span>
    </div>
    <div class="timing-item">
      <span class="timing-label">Size</span>
      <span class="timing-val">${req.size ? formatSize(req.size) : '—'}</span>
    </div>
    <div class="timing-item">
      <span class="timing-label">Initiator</span>
      <span class="timing-val" style="font-size:11px;letter-spacing:0;">${req.initiator_type || req.initiatorType || '—'}</span>
    </div>
  `;

  // Request headers
  renderHeaders('details-req-headers', req.headers || {});

  // Response headers
  renderHeaders('details-res-headers', req.response_headers || req.responseHeaders || {});

  // Response body
  const bodyEl = $('details-res-body');
  const bodySection = $('details-body-section');
  const body = req.response_body || req.responseBody;
  if (body !== null && body !== undefined) {
    const bodyStr = typeof body === 'object'
      ? JSON.stringify(body, null, 2)
      : String(body);
    bodyEl.textContent = bodyStr.slice(0, 8000);
    bodySection.classList.remove('hidden');
  } else {
    bodyEl.textContent = '';
    bodySection.classList.add('hidden');
  }

  // Hide replay result
  $('replay-result-section').classList.add('hidden');
  $('replay-result-body').textContent = '';

  // Show panel
  $('details-overlay').classList.remove('hidden');
  $('details-panel').classList.remove('hidden');
}

function renderHeaders(containerId, headers) {
  const el = $(containerId);
  if (!el) return;
  const entries = Object.entries(headers);
  if (!entries.length) {
    el.innerHTML = '<div style="padding:10px 18px;color:var(--muted);font-size:11px;">No headers</div>';
    return;
  }
  el.innerHTML = `<div class="headers-list">${
    entries.map(([k, v]) => `
      <div class="header-row">
        <span class="header-key">${escHtml(k)}:</span>
        <span class="header-val">${escHtml(String(v))}</span>
      </div>`).join('')
  }</div>`;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function closeDetails() {
  $('details-overlay').classList.add('hidden');
  $('details-panel').classList.add('hidden');
  state.selectedReqId = null;
  document.querySelectorAll('.req-table tbody tr').forEach(tr => tr.classList.remove('selected'));
  document.querySelectorAll('.wf-row').forEach(r => r.classList.remove('selected'));
}

// Collapsible sections
document.querySelectorAll('.collapsible').forEach(btn => {
  btn.addEventListener('click', () => {
    const targetId = btn.dataset.target;
    const body = $(targetId);
    if (!body) return;
    const isCollapsed = body.classList.contains('collapsed');
    body.classList.toggle('collapsed', !isCollapsed);
    btn.dataset.open = isCollapsed ? 'true' : 'false';
    // rotate arrow
    const arrow = btn.querySelector('.collapse-arrow');
    if (arrow) arrow.style.transform = isCollapsed ? 'rotate(180deg)' : '';
  });
});

// ── Replay Request ─────────────────────────────────────────────────────
$('details-replay-btn').addEventListener('click', async () => {
  const id = state.selectedReqId;
  if (!id) return;
  const req = state.requests.get(id);
  if (!req) return;

  const btn = $('details-replay-btn');
  btn.disabled = true;
  btn.innerHTML = `<svg viewBox="0 0 14 14" fill="none" style="animation:brandPulse .6s infinite"><path d="M2 7a5 5 0 1 0 1.5-3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><path d="M2 3.5V7H5.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg> Replaying…`;

  const resultSection = $('replay-result-section');
  const resultBody    = $('replay-result-body');
  const statusBadge   = $('replay-status-badge');

  try {
    const res = await fetch('/replay', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: req.url,
        method: req.method || 'GET',
        headers: req.headers || {},
      }),
    });
    const data = await res.json();

    statusBadge.textContent = data.status || 'Error';
    statusBadge.className = `status-badge ${statusClass(data.status, !!data.error)}`;

    const body = data.body;
    resultBody.textContent = typeof body === 'object'
      ? JSON.stringify(body, null, 2)
      : String(body || '').slice(0, 6000);

    resultSection.classList.remove('hidden');
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (err) {
    resultBody.textContent = 'Replay failed: ' + err.message;
    statusBadge.textContent = 'Error';
    statusBadge.className = 'status-badge status-failed';
    resultSection.classList.remove('hidden');
  }

  btn.disabled = false;
  btn.innerHTML = `<svg viewBox="0 0 14 14" fill="none"><path d="M2 7a5 5 0 1 0 1.5-3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><path d="M2 3.5V7H5.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg> Replay`;
});

// Close panel
$('details-close-btn').addEventListener('click', closeDetails);
$('details-overlay').addEventListener('click', closeDetails);

// ── WebSocket message handler ───────────────────────────────────────────
function handleMessage(msg) {
  switch (msg.type) {

    case 'status':
      setStatus('running', msg.message);
      break;

    case 'request': {
      const d = msg.data;
      const reqObj = {
        id: d.id, url: d.url, method: d.method,
        type: d.resourceType, start_time: d.startTime,
        relative_start: d.relativeStart,
        initiator_url: d.initiatorUrl,
        initiator_type: d.initiatorType,
        status: null, size: null, duration: null, failed: false,
      };
      state.requests.set(d.id, reqObj);

      // First request → HTTP request sent
      if (state.requests.size === 1) {
        setDone('dns', state.phaseTiming?.dns_ms);
        setDone('tcp', state.phaseTiming?.connect_ms);
        setDone('tls', state.phaseTiming?.ssl_ms);
        setActive('http', null);
      }
      addTableRow(reqObj);
      updateMetrics();

      // Live dep graph: update if that tab is visible
      if ($('tab-dependency') && $('tab-dependency').classList.contains('active')) {
        renderDependencyGraph();
      }
      break;
    }

    case 'response': {
      const d = msg.data;
      const req = state.requests.get(d.id);
      if (req) {
        req.status = d.status;
        req.size = d.size;
        req.duration = d.duration;
        req.response_headers = d.responseHeaders || {};
      }
      updateTableRow(d.id);
      updateMetrics();

      // Live dep graph update with status/size info
      if ($('tab-dependency') && $('tab-dependency').classList.contains('active')) {
        renderDependencyGraph();
      }
      break;
    }

    case 'request_failed': {
      const req = state.requests.get(msg.data.id);
      if (req) { req.failed = true; req.failure = msg.data.failure; }
      updateTableRow(msg.data.id);
      break;
    }

    case 'phase_timing': {
      state.phaseTiming = msg.data;
      const pt = msg.data;
      setDone('dns',    pt.dns_ms);
      setDone('tcp',    pt.connect_ms);
      setDone('tls',    pt.ssl_ms);
      setDone('http',   null);
      setActive('server', pt.ttfb_ms);
      setTimeout(() => {
        setDone('server', pt.ttfb_ms);
        setActive('html', pt.download_ms);
        setTimeout(() => setDone('html', pt.download_ms), 600);
      }, 400);
      $('pip-subtitle').textContent = `Analyzing ${$('url-input').value.trim()}…`;
      setProgress(65);
      updateMetrics();
      break;
    }

    case 'browser_timing': {
      state.browserTiming = msg.data;
      const bt = msg.data;
      setDone('html', state.phaseTiming?.download_ms);
      setActive('parse', null);
      setTimeout(() => {
        setDone('parse', null);
        setActive('cssjs', bt.dom_interactive != null ? Math.round(bt.dom_interactive) : null);
        setTimeout(() => {
          setDone('cssjs', bt.dom_interactive != null ? Math.round(bt.dom_interactive) : null);
          setActive('dom', bt.dom_ready != null ? Math.round(bt.dom_ready) : null);
          setTimeout(() => {
            setDone('dom', bt.dom_ready != null ? Math.round(bt.dom_ready) : null);
            setActive('load', bt.load_event != null ? Math.round(bt.load_event) : null);
          }, 400);
        }, 500);
      }, 300);
      setProgress(85);
      updateMetrics();
      break;
    }

    case 'navigate_error':
      setStatus('error', msg.message || 'Navigation error');
      break;

    case 'error':
      setStatus('error', msg.message || 'Unknown error');
      break;

    case 'complete': {
      // Merge full request data (includes response_body, headers, etc.)
      if (msg.requests) {
        msg.requests.forEach(r => {
          const ex = state.requests.get(r.id);
          if (ex) Object.assign(ex, r);
          else state.requests.set(r.id, r);
          updateTableRow(r.id);
        });
      }

      setTimeout(() => {
        STAGE_ORDER.forEach(key => {
          const el = $(STAGES[key].id);
          if (el && !el.classList.contains('is-done')) {
            const timingEl = $(STAGES[key].timingId);
            const ms = timingEl?.textContent || null;
            setDone(key, ms ? ms.replace('ms','') : undefined);
          }
        });
        const pt = state.phaseTiming;
        const bt = state.browserTiming;
        if (pt) { setDone('dns', pt.dns_ms); setDone('tcp', pt.connect_ms); setDone('tls', pt.ssl_ms); setDone('server', pt.ttfb_ms); setDone('html', pt.download_ms); }
        if (bt) { setDone('dom', bt.dom_ready != null ? Math.round(bt.dom_ready) : null); setDone('load', bt.load_event != null ? Math.round(bt.load_event) : null); }

        const allReqs = msg.requests || [...state.requests.values()];
        renderResourceBar(allReqs);

        // Show dev panel and auto-render dependency graph
        $('dev-panel').classList.remove('hidden');
        renderDependencyGraph();
      }, 200);

      state.exportData = {
        url: $('url-input').value.trim(),
        summary: msg.summary,
        phaseTiming: state.phaseTiming,
        browserTiming: state.browserTiming,
        requests: msg.requests || [...state.requests.values()],
        tree: msg.tree,
      };

      setStatus('done', `Done — ${state.requests.size} requests`);
      setProgress(100);
      $('progress-fill').classList.remove('progress-running');
      $('pip-subtitle').textContent = `Analysis complete — ${state.requests.size} requests captured`;
      $('export-btn').disabled = false;
      state.analyzing = false;
      $('analyze-btn').innerHTML = ANALYZE_BTN_HTML;
      $('analyze-btn').disabled = false;
      updateMetrics();
      break;
    }
  }
}

// ── Start analysis ──────────────────────────────────────────────────────
function startAnalysis() {
  const url = $('url-input').value.trim();
  if (!url) { $('url-input').focus(); return; }
  if (state.analyzing) return;

  // Reset
  state.requests.clear();
  state.phaseTiming   = null;
  state.browserTiming = null;
  state.exportData    = null;
  state.selectedReqId = null;

  resetAllStages();

  // Reset metrics (add loading pulse)
  ['v-load','v-dns','v-ttfb','v-dom','v-size','v-reqs'].forEach(id => {
    const el = $(id);
    if (!el) return;
    el.textContent = '—';
    el.classList.remove('metric-pop');
    el.classList.add('metric-loading');
  });
  $('tab-req-count').textContent = '0';

  // Reset table
  const tbody = $('req-table-body');
  if (tbody) tbody.innerHTML = '<tr class="req-table-empty"><td colspan="7">Waiting for requests…</td></tr>';

  // Reset waterfall
  const wf = $('waterfall-rows');
  if (wf) wf.innerHTML = '';
  const wfEmpty = $('waterfall-empty');
  if (wfEmpty) wfEmpty.style.display = 'block';

  // Reset dependency graph
  const dep = $('dep-tree');
  if (dep) dep.innerHTML = '<div class="dep-empty">Waiting for analysis…</div>';
  const depStats = $('dep-stats');
  if (depStats) depStats.innerHTML = '';

  // Hide sections
  $('resource-section').classList.add('hidden');
  $('dev-panel').classList.add('hidden');
  closeDetails();

  // Hide idle overlay
  const idleEl = $('pipeline-idle');
  if (idleEl) idleEl.classList.add('fade-out');
  setTimeout(() => { if (idleEl) idleEl.classList.add('hidden'); }, 500);

  // Show status strip
  $('status-strip').classList.remove('hidden');
  setStatus('running', 'Connecting…');

  // Snap progress to 0 without animation, then animate forward
  const fillEl = $('progress-fill');
  fillEl.style.transition = 'none';
  fillEl.style.width = '0%';
  void fillEl.offsetWidth; // force reflow
  fillEl.style.transition = '';
  fillEl.classList.add('progress-running');
  setProgress(5);

  // Disable export while new analysis runs
  $('export-btn').disabled = true;

  // Show spinner on analyze button
  $('analyze-btn').innerHTML = `<svg class="btn-spinner" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="5.5" stroke="currentColor" stroke-width="1.6" stroke-dasharray="26" stroke-dashoffset="8"/></svg> Analyzing…`;

  $('pip-subtitle').textContent = `Connecting to ${url}…`;

  pendingAllStages();

  if (state.ws) { try { state.ws.close(); } catch {} }

  const wsProto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${wsProto}://${location.host}/ws`);
  state.ws = ws;

  ws.onopen = () => {
    ws.send(JSON.stringify({ url }));
    setStatus('running', `Analyzing ${url}…`);
    setProgress(15);
  };

  ws.onmessage = evt => {
    let msg;
    try { msg = JSON.parse(evt.data); } catch { return; }
    handleMessage(msg);
  };

  ws.onclose = () => {
    state.analyzing = false;
    $('analyze-btn').innerHTML = ANALYZE_BTN_HTML;
    $('analyze-btn').disabled = false;
    $('progress-fill').classList.remove('progress-running');
    if ($('progress-fill').style.width !== '100%') {
      setStatus('done', 'Connection closed');
      setProgress(100);
    }
  };

  ws.onerror = () => {
    setStatus('error', 'WebSocket error — is the backend running?');
    state.analyzing = false;
    $('analyze-btn').innerHTML = ANALYZE_BTN_HTML;
    $('analyze-btn').disabled = false;
    $('progress-fill').classList.remove('progress-running');
  };

  state.analyzing = true;
  $('analyze-btn').disabled = true;
}

// ── Export ──────────────────────────────────────────────────────────────
function exportJson() {
  if (!state.exportData) return;
  const blob = new Blob([JSON.stringify(state.exportData, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `web-analysis-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── Event listeners ─────────────────────────────────────────────────────
$('analyze-btn').addEventListener('click', startAnalysis);
$('export-btn').addEventListener('click', exportJson);
$('url-input').addEventListener('keydown', e => { if (e.key === 'Enter') startAnalysis(); });
