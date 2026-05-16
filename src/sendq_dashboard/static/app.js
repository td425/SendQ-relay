/* SendQ Dashboard — vanilla JS SPA.
 *
 * Auth: session cookie + CSRF token from <meta name=csrf-token>.
 * On 401 the user is redirected to /login.
 * Every mutation triggers a re-fetch of the affected resource
 * to avoid stale UI without a hard refresh.
 */
'use strict';

const CSRF = document.querySelector('meta[name=csrf-token]').content;
let ME = null;

/* ── HTTP helper ───────────────────────────────────────────── */
async function api(url, opts = {}) {
  const headers = Object.assign(
    { 'Content-Type': 'application/json' },
    opts.headers || {},
  );
  if (opts.method && opts.method !== 'GET') {
    headers['X-CSRF-Token'] = CSRF;
  }
  let r;
  try {
    r = await fetch(url, { ...opts, headers, credentials: 'same-origin' });
  } catch (e) {
    return { status: 'error', message: 'Network error: ' + e.message };
  }
  if (r.status === 401) {
    window.location = '/login';
    return { status: 'error', message: 'unauthorized' };
  }
  let body;
  try { body = await r.json(); } catch { body = { status: 'error', message: 'Bad response' }; }
  if (!r.ok && body.status !== 'error') body.status = 'error';
  return body;
}

function toast(msg, kind = 'ok') {
  const c = document.getElementById('toast-c');
  const d = document.createElement('div');
  d.className = 'toast ' + kind;
  d.textContent = msg;
  c.appendChild(d);
  setTimeout(() => d.remove(), 3500);
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtTs(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    });
  } catch { return iso; }
}

function fmtSize(n) {
  if (!n && n !== 0) return '—';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(2) + ' MB';
}

/* ── Navigation ────────────────────────────────────────────── */
const NAV_ADMIN = [
  { id: 'dashboard', label: 'Dashboard',     render: viewDashboard },
  { id: 'messages',  label: 'Messages',      render: viewMessages },
  { id: 'logs',      label: 'Raw logs',      render: viewLogs },
  { id: 'queue',     label: 'Queue',         render: viewQueue },
  { id: 'domains',   label: 'Domains',       render: viewDomains },
  { id: 'dkim',      label: 'DKIM',          render: viewDkim },
  { id: 'mta-users', label: 'MTA users',     render: viewMtaUsers },
  { id: 'portal',    label: 'Portal users',  render: viewPortalUsers },
  { id: 'relay',     label: 'Relay',         render: viewRelay },
  { id: 'config',    label: 'Configuration', render: viewConfig },
  { id: 'health',    label: 'Health',        render: viewHealth },
];
const NAV_USER = [
  { id: 'dashboard', label: 'Dashboard',  render: viewDashboard },
  { id: 'messages',  label: 'My messages', render: viewMessages },
  { id: 'logs',      label: 'Raw logs',   render: viewLogs },
  { id: 'domains',   label: 'My domains', render: viewDomains },
];

function buildNav() {
  const nav = document.getElementById('nav');
  const items = ME.role === 'admin' ? NAV_ADMIN : NAV_USER;
  nav.innerHTML = '';
  for (const item of items) {
    const a = document.createElement('a');
    a.textContent = item.label;
    a.dataset.id = item.id;
    a.onclick = () => go(item.id);
    nav.appendChild(a);
  }
}

function go(id) {
  const items = ME.role === 'admin' ? NAV_ADMIN : NAV_USER;
  const target = items.find(i => i.id === id) || items[0];
  for (const a of document.querySelectorAll('#nav a')) {
    a.classList.toggle('active', a.dataset.id === target.id);
  }
  document.getElementById('top-title').textContent = target.label;
  const root = document.getElementById('content');
  root.innerHTML = '<p class="empty">Loading…</p>';
  Promise.resolve(target.render(root)).catch(e => {
    console.error(e);
    root.innerHTML = '<p class="empty">Error: ' + esc(e.message) + '</p>';
  });
}

/* ── Boot ──────────────────────────────────────────────────── */
(async function boot() {
  const r = await api('/api/me');
  if (r.status !== 'ok' || !r.data) {
    window.location = '/login';
    return;
  }
  ME = r.data;
  document.getElementById('me-name').textContent = ME.username;
  document.getElementById('me-role').textContent = ME.role;
  buildNav();
  refreshServerState();
  setInterval(refreshServerState, 10000);
  go('dashboard');
})();

async function refreshServerState() {
  const r = await api('/api/status');
  if (r.status !== 'ok') return;
  const el = document.getElementById('server-state');
  if (r.server && r.server.running) {
    el.innerHTML = '<span class="pill ok">Running · PID ' + r.server.pid + '</span>';
  } else {
    el.innerHTML = '<span class="pill err">Stopped</span>';
  }
}

/* ── Dashboard view ───────────────────────────────────────── */
async function viewDashboard(root) {
  const r = await api('/api/status');
  if (r.status !== 'ok') { root.innerHTML = '<p class="empty">Status unavailable.</p>'; return; }
  const q = r.queue || {};
  root.innerHTML = `
    <div class="grid metrics">
      <div class="card"><h3>Active queue</h3><div class="metric">${q.active||0}</div></div>
      <div class="card"><h3>Deferred</h3><div class="metric" style="color:var(--warn)">${q.deferred||0}</div></div>
      <div class="card"><h3>Failed</h3><div class="metric" style="color:var(--err)">${q.failed||0}</div></div>
      <div class="card"><h3>Relay</h3><div class="metric" style="font-size:16px">${
        r.relay && r.relay.enabled ? esc(r.relay.host) + ':' + r.relay.port : 'Direct MX'
      }</div></div>
    </div>
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(280px,1fr))">
      <div class="card">
        <h3>Server</h3>
        <p>Hostname: <b>${esc((r.server||{}).hostname||'-')}</b></p>
        <p>Version: ${esc((r.server||{}).version||'-')}</p>
        <p>State: ${(r.server||{}).running ? '<span class="badge delivered">Running</span>' : '<span class="badge failed">Stopped</span>'}</p>
      </div>
      <div class="card">
        <h3>Features</h3>
        ${['dkim','spf','dmarc','rate_limiting'].map(k =>
          `<p>${k.toUpperCase()}: ${
            (r.features||{})[k] ? '<span class="badge delivered">ON</span>' : '<span class="badge queued">OFF</span>'
          }</p>`).join('')}
      </div>
      <div class="card">
        <h3>Listeners</h3>
        ${(r.listeners||[]).map(l =>
          `<p>${esc(l.name)} · ${esc(l.address)}:${l.port} · ${esc(l.tls_mode)}${l.require_auth?' · AUTH':''}</p>`
        ).join('') || '<p class="empty">None</p>'}
      </div>
    </div>
  `;
}

/* ── Messages (detailed log timeline) ────────────────────── */
async function viewMessages(root) {
  root.innerHTML = `
    <div class="filters">
      <div class="row"><label>Status</label>
        <select id="f-status">
          <option value="">Any</option>
          <option value="delivered">Delivered</option>
          <option value="deferred">Deferred</option>
          <option value="failed">Failed</option>
          <option value="delivering">Delivering</option>
          <option value="queued">Queued</option>
        </select>
      </div>
      <div class="row"><label>Domain</label><input id="f-domain" placeholder="example.com"></div>
      <div class="row"><label>Sender contains</label><input id="f-sender"></div>
      <div class="row"><label>Recipient contains</label><input id="f-rcpt"></div>
      <div class="row"><label>Search</label><input id="f-q" placeholder="msg-id or error text"></div>
      <button class="btn primary" id="f-go">Search</button>
      <button class="btn" id="f-refresh">Refresh</button>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <table class="tbl">
        <thead><tr>
          <th>Received</th><th>Status</th><th>From</th><th>To</th>
          <th>Size</th><th>From IP</th><th>Message ID</th>
        </tr></thead>
        <tbody id="msg-body"><tr><td colspan="7" class="empty">Loading…</td></tr></tbody>
      </table>
    </div>
    <div id="msg-pager" style="margin-top:12px;color:var(--muted);font-size:12px"></div>
  `;
  let page = 1;
  async function load() {
    const params = new URLSearchParams({
      page: page,
      page_size: 100,
      status: document.getElementById('f-status').value,
      domain: document.getElementById('f-domain').value,
      sender: document.getElementById('f-sender').value,
      recipient: document.getElementById('f-rcpt').value,
      q: document.getElementById('f-q').value,
    });
    const r = await api('/api/messages?' + params);
    const tb = document.getElementById('msg-body');
    if (r.status !== 'ok') { tb.innerHTML = '<tr><td colspan="7" class="empty">' + esc(r.message) + '</td></tr>'; return; }
    if (!r.data.length) { tb.innerHTML = '<tr><td colspan="7" class="empty">No messages match.</td></tr>'; }
    else {
      tb.innerHTML = r.data.map(m => `
        <tr class="msg-row" data-id="${esc(m.msg_id)}">
          <td>${esc(fmtTs(m.received_at))}</td>
          <td><span class="badge ${esc(m.status)}">${esc(m.status)}</span></td>
          <td>${esc(m.sender)}</td>
          <td>${esc((m.recipients||[]).slice(0,3).join(', ')) + ((m.recipients||[]).length > 3 ? ` +${m.recipients.length-3}` : '')}</td>
          <td>${esc(fmtSize(m.size_bytes))}</td>
          <td class="id">${esc(m.peer_ip)}</td>
          <td class="id">${esc(m.msg_id)}</td>
        </tr>
      `).join('');
      tb.querySelectorAll('.msg-row').forEach(tr => {
        tr.onclick = () => toggleDetail(tr);
      });
    }
    document.getElementById('msg-pager').textContent =
      `Page ${page} · ${r.data.length} of ${r.total} matching messages`;
  }
  document.getElementById('f-go').onclick = () => { page = 1; load(); };
  document.getElementById('f-refresh').onclick = load;
  load();
}

async function toggleDetail(tr) {
  const existing = tr.nextElementSibling;
  if (existing && existing.classList.contains('detail-row')) {
    existing.remove();
    tr.classList.remove('expanded');
    return;
  }
  tr.classList.add('expanded');
  const dr = document.createElement('tr');
  dr.className = 'detail-row';
  dr.innerHTML = '<td colspan="7" class="empty">Loading…</td>';
  tr.after(dr);
  const id = tr.dataset.id;
  const r = await api('/api/messages/' + encodeURIComponent(id));
  if (r.status !== 'ok') { dr.firstElementChild.textContent = r.message; return; }
  const m = r.data;
  const steps = [
    { ts: m.received_at, label: 'Received', cls: '', resp: `from ${m.peer_ip} · ${fmtSize(m.size_bytes)}` },
    ...(m.attempts || []).map(a => ({
      ts: a.attempt_at,
      label: a.outcome === 'success' ? 'Delivered'
            : a.outcome === 'deferred' ? 'Deferred' : 'Failed',
      cls: a.outcome === 'success' ? 'success'
         : a.outcome === 'deferred' ? 'deferred' : 'failed',
      resp: `${a.remote_host||'—'}${a.smtp_code?' · '+a.smtp_code:''}${a.smtp_resp?' · '+a.smtp_resp:''}`,
    })),
  ];
  if (m.finalized_at && m.status === 'delivered') {
    // already covered by last attempt
  } else if (m.finalized_at) {
    steps.push({
      ts: m.finalized_at,
      label: 'Final: ' + m.status,
      cls: m.status,
      resp: m.last_error || '',
    });
  }
  dr.firstElementChild.innerHTML = `
    <div><b>Recipients:</b> ${esc((m.recipients||[]).join(', '))}</div>
    <div style="margin:10px 0 8px"><b>Timeline:</b></div>
    <div class="timeline">
      ${steps.map(s => `
        <div class="step ${esc(s.cls)}">
          <span class="ts">${esc(fmtTs(s.ts))}</span>
          <b>${esc(s.label)}</b>
          <span class="resp">${esc(s.resp)}</span>
        </div>
      `).join('')}
    </div>
  `;
}

/* ── Raw logs view ────────────────────────────────────────── */
async function viewLogs(root) {
  root.innerHTML = `
    <div class="filters">
      <div class="row"><label>Lines</label><input id="lg-n" type="number" value="200" min="10" max="2000" style="width:90px"></div>
      <div class="row"><label>Level</label><select id="lg-lvl">
        <option value="">Any</option><option>error</option><option>warning</option><option>info</option><option>debug</option>
      </select></div>
      <div class="row"><label>Search</label><input id="lg-q"></div>
      <button class="btn primary" id="lg-go">Reload</button>
      <label style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)">
        <input type="checkbox" id="lg-auto"> Auto-refresh (5s)
      </label>
    </div>
    <div class="log-pane" id="lg-pane"><div class="empty">Loading…</div></div>
  `;
  let iv = null;
  async function load() {
    const p = new URLSearchParams({
      lines: document.getElementById('lg-n').value,
      level: document.getElementById('lg-lvl').value,
      search: document.getElementById('lg-q').value,
    });
    const r = await api('/api/logs?' + p);
    const pane = document.getElementById('lg-pane');
    if (r.status !== 'ok') { pane.innerHTML = '<div class="empty">' + esc(r.message) + '</div>'; return; }
    pane.innerHTML = r.data.map(line => {
      let cls = '';
      if (/error/i.test(line)) cls = 'lvl-error';
      else if (/warn/i.test(line)) cls = 'lvl-warn';
      else if (/info/i.test(line)) cls = 'lvl-info';
      return `<div class="${cls}">${line}</div>`;  // already escaped server-side
    }).join('') || '<div class="empty">No matching log lines.</div>';
  }
  document.getElementById('lg-go').onclick = load;
  document.getElementById('lg-auto').onchange = e => {
    if (iv) clearInterval(iv);
    if (e.target.checked) iv = setInterval(load, 5000);
  };
  load();
}

/* ── Queue view ───────────────────────────────────────────── */
async function viewQueue(root) {
  root.innerHTML = `
    <div class="filters">
      <div class="row"><label>Type</label><select id="q-type">
        <option value="all">All</option>
        <option value="active">Active</option>
        <option value="deferred">Deferred</option>
        <option value="failed">Failed</option>
      </select></div>
      <button class="btn primary" id="q-load">Refresh</button>
      <button class="btn danger" id="q-flush">Flush active</button>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <table class="tbl">
        <thead><tr><th>Queue</th><th>Msg ID</th><th>Sender</th><th>Recipients</th><th>Retry</th><th></th></tr></thead>
        <tbody id="q-body"><tr><td colspan="6" class="empty">Loading…</td></tr></tbody>
      </table>
    </div>
  `;
  async function load() {
    const type = document.getElementById('q-type').value;
    const r = await api('/api/queue/list?type=' + encodeURIComponent(type));
    const tb = document.getElementById('q-body');
    if (r.status !== 'ok') { tb.innerHTML = '<tr><td colspan="6" class="empty">' + esc(r.message) + '</td></tr>'; return; }
    if (!r.data.length) { tb.innerHTML = '<tr><td colspan="6" class="empty">Queue is empty.</td></tr>'; return; }
    tb.innerHTML = r.data.map(m => `
      <tr>
        <td><span class="badge ${esc(m.queue==='active'?'queued':m.queue)}">${esc(m.queue)}</span></td>
        <td class="id">${esc(m.msg_id)}</td>
        <td>${esc(m.sender)}</td>
        <td>${esc((m.recipients||[]).join(', '))}</td>
        <td>${m.retry_count||0}</td>
        <td class="actions">
          <button class="btn small danger" data-del="${esc(m.msg_id)}">Delete</button>
        </td>
      </tr>
    `).join('');
    tb.querySelectorAll('button[data-del]').forEach(b => {
      b.onclick = async () => {
        if (!confirm('Delete this message?')) return;
        const x = await api('/api/queue/delete', { method: 'POST', body: JSON.stringify({ msg_id: b.dataset.del }) });
        if (x.status === 'ok') { toast('Deleted'); load(); }
        else toast(x.message, 'err');
      };
    });
  }
  document.getElementById('q-type').onchange = load;
  document.getElementById('q-load').onclick = load;
  document.getElementById('q-flush').onclick = async () => {
    if (!confirm('Flush all active queue messages?')) return;
    const x = await api('/api/queue/flush', { method: 'POST' });
    if (x.status === 'ok') { toast(`Flushed ${x.flushed} messages`); load(); }
    else toast(x.message, 'err');
  };
  load();
}

/* ── Domains view ─────────────────────────────────────────── */
async function viewDomains(root) {
  const isAdmin = ME.role === 'admin';
  root.innerHTML = `
    ${isAdmin ? `
      <div class="card" style="margin-bottom:16px">
        <h3>Add domain</h3>
        <div style="display:flex;gap:10px;align-items:end;flex-wrap:wrap">
          <input id="d-name" placeholder="example.com" style="flex:1;min-width:200px;background:#11141c;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px">
          <select id="d-type" style="background:#11141c;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px">
            <option value="local">Local</option>
            <option value="relay">Relay</option>
            <option value="blocked">Blocked</option>
          </select>
          <button class="btn primary" id="d-add">Add</button>
        </div>
      </div>
    ` : ''}
    <div id="d-cards" class="grid" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr))"></div>
  `;
  async function load() {
    const r = await api('/api/domains');
    if (r.status !== 'ok') return;
    const wrap = document.getElementById('d-cards');
    const renderList = (title, list, type) => `
      <div class="card">
        <h3>${esc(title)} (${list.length})</h3>
        ${list.length ? `<table class="tbl"><tbody>${
          list.map(d => `
            <tr><td>${esc(d)}</td>
            ${isAdmin ? `<td class="actions"><button class="btn small danger" data-rm="${esc(d)}" data-type="${esc(type)}">Remove</button></td>` : ''}
            </tr>`).join('')
        }</tbody></table>` : '<p class="empty">None</p>'}
      </div>`;
    wrap.innerHTML = renderList('Local domains', r.data.local || [], 'local')
                   + renderList('Relay domains', r.data.relay || [], 'relay')
                   + renderList('Blocked domains', r.data.blocked || [], 'blocked');
    wrap.querySelectorAll('button[data-rm]').forEach(b => {
      b.onclick = async () => {
        if (!confirm(`Remove ${b.dataset.rm}?`)) return;
        const x = await api('/api/domains/' + encodeURIComponent(b.dataset.rm) + '?type=' + b.dataset.type, { method: 'DELETE' });
        if (x.status === 'ok') { toast('Removed'); load(); }
        else toast(x.message, 'err');
      };
    });
  }
  if (isAdmin) {
    document.getElementById('d-add').onclick = async () => {
      const domain = document.getElementById('d-name').value.trim();
      const type = document.getElementById('d-type').value;
      if (!domain) return;
      const x = await api('/api/domains', { method: 'POST', body: JSON.stringify({ domain, type }) });
      if (x.status === 'ok') { toast('Added'); document.getElementById('d-name').value = ''; load(); }
      else toast(x.message, 'err');
    };
  }
  load();
}

/* ── DKIM view ────────────────────────────────────────────── */
async function viewDkim(root) {
  root.innerHTML = '<div id="dk-wrap"><p class="empty">Loading…</p></div>';
  async function load() {
    const r = await api('/api/dkim');
    if (r.status !== 'ok') { document.getElementById('dk-wrap').innerHTML = '<p class="empty">' + esc(r.message) + '</p>'; return; }
    const d = r.data;
    document.getElementById('dk-wrap').innerHTML = `
      <div class="card" style="margin-bottom:14px">
        <h3>DKIM signing</h3>
        <p>Status: ${d.enabled ? '<span class="badge delivered">Enabled</span>' : '<span class="badge queued">Disabled</span>'}
        <button class="btn small" id="dk-toggle" style="margin-left:8px">Toggle</button></p>
        <p>Selector: <b>${esc(d.selector)}</b></p>
        <p>Key directory: <code>${esc(d.key_dir)}</code></p>
      </div>
      <div class="card" style="margin-bottom:14px">
        <h3>Generate key</h3>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end">
          <input id="dk-domain" placeholder="example.com" style="background:#11141c;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px;flex:1;min-width:180px">
          <input id="dk-sel" placeholder="${esc(d.selector)}" style="background:#11141c;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px;width:120px">
          <select id="dk-bits" style="background:#11141c;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px">
            <option>2048</option><option>1024</option><option>4096</option>
          </select>
          <button class="btn primary" id="dk-gen">Generate</button>
        </div>
      </div>
      <div class="card" style="padding:0">
        <h3 style="padding:14px 14px 0">Signing domains (${d.domains.length})</h3>
        ${d.domains.length ? d.domains.map(dom => `
          <div class="dkim-domain">
            <div class="domain-head">
              <span class="domain-name">${esc(dom.domain)}</span>
              <span>
                ${dom.key_present ? '<span class="badge delivered">Key OK</span>' : '<span class="badge failed">Missing key</span>'}
                <button class="btn small danger" data-del="${esc(dom.domain)}" style="margin-left:8px">Remove</button>
              </span>
            </div>
            <div style="color:var(--muted);font-size:12px">selector: ${esc(dom.selector)} · key: <code>${esc(dom.key_path)}</code></div>
            ${dom.dns_record ? `<div class="dns">${esc(dom.dns_record)}</div>` : ''}
          </div>
        `).join('') : '<p class="empty">No signing domains configured.</p>'}
      </div>
    `;
    document.getElementById('dk-toggle').onclick = async () => {
      const x = await api('/api/dkim/toggle', { method: 'POST' });
      if (x.status === 'ok') { toast('DKIM ' + (x.enabled?'enabled':'disabled')); load(); }
    };
    document.getElementById('dk-gen').onclick = async () => {
      const domain = document.getElementById('dk-domain').value.trim();
      const selector = document.getElementById('dk-sel').value.trim() || d.selector;
      const bits = parseInt(document.getElementById('dk-bits').value);
      if (!domain) return;
      const x = await api('/api/dkim/keys', { method: 'POST', body: JSON.stringify({ domain, selector, bits }) });
      if (x.status === 'ok') { toast('Key generated for ' + domain); load(); }
      else toast(x.message, 'err');
    };
    document.querySelectorAll('button[data-del]').forEach(b => {
      b.onclick = async () => {
        if (!confirm('Remove DKIM key for ' + b.dataset.del + '?')) return;
        const x = await api('/api/dkim/keys/' + encodeURIComponent(b.dataset.del), { method: 'DELETE' });
        if (x.status === 'ok') { toast('Removed'); load(); }
        else toast(x.message, 'err');
      };
    });
  }
  load();
}

/* ── MTA users (SMTP-AUTH) view ──────────────────────────── */
async function viewMtaUsers(root) {
  root.innerHTML = `
    <div class="card" style="margin-bottom:14px">
      <h3>Add SMTP user</h3>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end">
        <input id="u-name" placeholder="username" style="background:#11141c;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px">
        <input id="u-email" placeholder="email" style="background:#11141c;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px">
        <input id="u-pw" type="password" placeholder="password (min 12)" style="background:#11141c;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px">
        <button class="btn primary" id="u-add">Add</button>
      </div>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <table class="tbl">
        <thead><tr><th>Username</th><th>Email</th><th>Display name</th><th>Enabled</th><th>Last login</th><th></th></tr></thead>
        <tbody id="u-body"><tr><td colspan="6" class="empty">Loading…</td></tr></tbody>
      </table>
    </div>
  `;
  async function load() {
    const r = await api('/api/users');
    const tb = document.getElementById('u-body');
    if (r.status !== 'ok') { tb.innerHTML = '<tr><td colspan="6" class="empty">' + esc(r.message) + '</td></tr>'; return; }
    if (!r.data.length) { tb.innerHTML = '<tr><td colspan="6" class="empty">No SMTP users.</td></tr>'; return; }
    tb.innerHTML = r.data.map(u => `
      <tr>
        <td>${esc(u.username)}</td>
        <td>${esc(u.email)}</td>
        <td>${esc(u.display_name)}</td>
        <td>${u.enabled ? '<span class="badge delivered">Yes</span>' : '<span class="badge failed">No</span>'}</td>
        <td>${esc(fmtTs(u.last_login))}</td>
        <td class="actions">
          <button class="btn small" data-pw="${esc(u.username)}">Reset PW</button>
          <button class="btn small" data-toggle="${esc(u.username)}" data-en="${u.enabled?'1':'0'}">${u.enabled?'Disable':'Enable'}</button>
          <button class="btn small danger" data-del="${esc(u.username)}">Delete</button>
        </td>
      </tr>
    `).join('');
    tb.querySelectorAll('button[data-pw]').forEach(b => {
      b.onclick = async () => {
        const pw = prompt('New password (min 12 chars) for ' + b.dataset.pw);
        if (!pw) return;
        const x = await api('/api/users/' + encodeURIComponent(b.dataset.pw) + '/password',
          { method: 'POST', body: JSON.stringify({ password: pw }) });
        toast(x.status === 'ok' ? 'Password reset' : x.message, x.status==='ok'?'ok':'err');
      };
    });
    tb.querySelectorAll('button[data-toggle]').forEach(b => {
      b.onclick = async () => {
        const x = await api('/api/users/' + encodeURIComponent(b.dataset.toggle),
          { method: 'PUT', body: JSON.stringify({ enabled: b.dataset.en !== '1' }) });
        if (x.status === 'ok') load(); else toast(x.message, 'err');
      };
    });
    tb.querySelectorAll('button[data-del]').forEach(b => {
      b.onclick = async () => {
        if (!confirm('Delete SMTP user ' + b.dataset.del + '?')) return;
        const x = await api('/api/users/' + encodeURIComponent(b.dataset.del), { method: 'DELETE' });
        if (x.status === 'ok') { toast('Deleted'); load(); } else toast(x.message, 'err');
      };
    });
  }
  document.getElementById('u-add').onclick = async () => {
    const username = document.getElementById('u-name').value.trim();
    const email = document.getElementById('u-email').value.trim();
    const password = document.getElementById('u-pw').value;
    if (!username || !password) { toast('Username and password required', 'err'); return; }
    const x = await api('/api/users', { method: 'POST', body: JSON.stringify({ username, password, email }) });
    if (x.status === 'ok') {
      toast('User added'); document.getElementById('u-name').value = '';
      document.getElementById('u-email').value = ''; document.getElementById('u-pw').value = '';
      load();
    } else toast(x.message, 'err');
  };
  load();
}

/* ── Portal users view ────────────────────────────────────── */
async function viewPortalUsers(root) {
  root.innerHTML = `
    <div class="card" style="margin-bottom:14px">
      <h3>Add portal user</h3>
      <p style="color:var(--muted);font-size:12px;margin-top:0">
        Portal users log into this dashboard only. They have no SMTP send rights.
      </p>
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:end">
        <input id="p-name" placeholder="username" style="background:#11141c;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px">
        <input id="p-pw" type="password" placeholder="password (min 12)" style="background:#11141c;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px">
        <select id="p-role" style="background:#11141c;border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:5px">
          <option value="user">User</option><option value="admin">Admin</option>
        </select>
        <button class="btn primary" id="p-add">Add</button>
      </div>
    </div>
    <div class="card" style="padding:0;overflow:hidden">
      <table class="tbl">
        <thead><tr><th>Username</th><th>Role</th><th>TOTP</th><th>Enabled</th><th>Assigned domains</th><th>Last login</th><th></th></tr></thead>
        <tbody id="p-body"><tr><td colspan="7" class="empty">Loading…</td></tr></tbody>
      </table>
    </div>
  `;
  async function load() {
    const r = await api('/api/portal-users');
    const tb = document.getElementById('p-body');
    if (r.status !== 'ok') { tb.innerHTML = '<tr><td colspan="7" class="empty">' + esc(r.message) + '</td></tr>'; return; }
    if (!r.data.length) { tb.innerHTML = '<tr><td colspan="7" class="empty">No portal users.</td></tr>'; return; }
    tb.innerHTML = r.data.map(u => `
      <tr>
        <td>${esc(u.username)}</td>
        <td><span class="badge ${u.role==='admin'?'delivering':'queued'}">${esc(u.role)}</span></td>
        <td>${u.totp_enrolled ? '<span class="badge delivered">Yes</span>' : '<span class="badge queued">No</span>'}</td>
        <td>${u.enabled ? '<span class="badge delivered">Yes</span>' : '<span class="badge failed">No</span>'}${u.locked?' <span class="badge failed">Locked</span>':''}</td>
        <td>${esc((u.assigned_domains||[]).join(', ')) || '<i style="color:var(--muted)">—</i>'}</td>
        <td>${esc(fmtTs(u.last_login))}</td>
        <td class="actions">
          <button class="btn small" data-assign="${esc(u.username)}" data-current="${esc((u.assigned_domains||[]).join(','))}">Domains</button>
          <button class="btn small" data-pw="${esc(u.username)}">Reset PW</button>
          ${u.totp_enrolled ? `<button class="btn small" data-totp="${esc(u.username)}">Disable TOTP</button>` : ''}
          <button class="btn small" data-toggle="${esc(u.username)}" data-en="${u.enabled?'1':'0'}">${u.enabled?'Disable':'Enable'}</button>
          <button class="btn small danger" data-del="${esc(u.username)}">Delete</button>
        </td>
      </tr>
    `).join('');
    tb.querySelectorAll('button[data-assign]').forEach(b => {
      b.onclick = async () => {
        const v = prompt(`Assigned domains for ${b.dataset.assign} (comma-separated):`, b.dataset.current);
        if (v === null) return;
        const list = v.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
        const x = await api('/api/portal-users/' + encodeURIComponent(b.dataset.assign),
          { method: 'PUT', body: JSON.stringify({ assigned_domains: list }) });
        if (x.status === 'ok') { toast('Updated'); load(); } else toast(x.message, 'err');
      };
    });
    tb.querySelectorAll('button[data-pw]').forEach(b => {
      b.onclick = async () => {
        const pw = prompt('New password (min 12) for ' + b.dataset.pw);
        if (!pw) return;
        const x = await api('/api/portal-users/' + encodeURIComponent(b.dataset.pw) + '/password',
          { method: 'POST', body: JSON.stringify({ password: pw }) });
        toast(x.status === 'ok' ? 'Password reset' : x.message, x.status==='ok'?'ok':'err');
      };
    });
    tb.querySelectorAll('button[data-totp]').forEach(b => {
      b.onclick = async () => {
        if (!confirm('Disable TOTP for ' + b.dataset.totp + '?')) return;
        const x = await api('/api/portal-users/' + encodeURIComponent(b.dataset.totp) + '/totp',
          { method: 'DELETE' });
        if (x.status === 'ok') { toast('TOTP disabled'); load(); }
      };
    });
    tb.querySelectorAll('button[data-toggle]').forEach(b => {
      b.onclick = async () => {
        const x = await api('/api/portal-users/' + encodeURIComponent(b.dataset.toggle),
          { method: 'PUT', body: JSON.stringify({ enabled: b.dataset.en !== '1' }) });
        if (x.status === 'ok') load();
      };
    });
    tb.querySelectorAll('button[data-del]').forEach(b => {
      b.onclick = async () => {
        if (!confirm('Delete portal user ' + b.dataset.del + '?')) return;
        const x = await api('/api/portal-users/' + encodeURIComponent(b.dataset.del), { method: 'DELETE' });
        if (x.status === 'ok') { toast('Deleted'); load(); }
      };
    });
  }
  document.getElementById('p-add').onclick = async () => {
    const username = document.getElementById('p-name').value.trim();
    const password = document.getElementById('p-pw').value;
    const role = document.getElementById('p-role').value;
    if (!username || !password) { toast('Username and password required', 'err'); return; }
    const x = await api('/api/portal-users', { method: 'POST', body: JSON.stringify({ username, password, role }) });
    if (x.status === 'ok') {
      toast('User added'); document.getElementById('p-name').value = '';
      document.getElementById('p-pw').value = ''; load();
    } else toast(x.message, 'err');
  };
  load();
}

/* ── Relay view ───────────────────────────────────────────── */
async function viewRelay(root) {
  const r = await api('/api/relay');
  if (r.status !== 'ok') { root.innerHTML = '<p class="empty">' + esc(r.message) + '</p>'; return; }
  const re = r.data;
  root.innerHTML = `
    <div class="card">
      <h3>Primary relay</h3>
      <form class="form" id="rl-form">
        <div class="row"><label>Enabled</label><input type="checkbox" id="rl-en" ${re.enabled?'checked':''}></div>
        <div class="row"><label>Host</label><input type="text" id="rl-host" value="${esc(re.host||'')}"></div>
        <div class="row"><label>Port</label><input type="number" id="rl-port" value="${re.port||587}"></div>
        <div class="row"><label>Username</label><input type="text" id="rl-user" value="${esc(re.username||'')}"></div>
        <div class="row"><label>Password</label><input type="password" id="rl-pw" value="${esc(re.password||'')}" placeholder="leave masked to keep existing"></div>
        <div class="row"><label>TLS mode</label><select id="rl-tls">
          <option ${re.tls_mode==='none'?'selected':''}>none</option>
          <option ${re.tls_mode==='starttls'?'selected':''}>starttls</option>
          <option ${re.tls_mode==='implicit'?'selected':''}>implicit</option>
        </select></div>
        <div class="row"><label>Verify TLS</label><input type="checkbox" id="rl-verify" ${re.tls_verify!==false?'checked':''}></div>
        <div style="display:flex;gap:8px">
          <button type="button" class="btn primary" id="rl-save">Save & reload</button>
          <button type="button" class="btn" id="rl-test">Test connection</button>
        </div>
      </form>
    </div>
  `;
  document.getElementById('rl-save').onclick = async () => {
    const body = {
      enabled: document.getElementById('rl-en').checked,
      host: document.getElementById('rl-host').value.trim(),
      port: parseInt(document.getElementById('rl-port').value),
      username: document.getElementById('rl-user').value.trim(),
      password: document.getElementById('rl-pw').value,
      tls_mode: document.getElementById('rl-tls').value,
      tls_verify: document.getElementById('rl-verify').checked,
    };
    const x = await api('/api/relay', { method: 'PUT', body: JSON.stringify(body) });
    toast(x.status==='ok'?'Saved':x.message, x.status==='ok'?'ok':'err');
  };
  document.getElementById('rl-test').onclick = async () => {
    const x = await api('/api/relay/test', { method: 'POST', body: JSON.stringify({
      host: document.getElementById('rl-host').value.trim(),
      port: parseInt(document.getElementById('rl-port').value),
    })});
    if (x.status === 'ok' && x.data.reachable) toast('Relay reachable');
    else toast(x.data?.error || x.message || 'Unreachable', 'err');
  };
}

/* ── Configuration form view ─────────────────────────────── */
async function viewConfig(root) {
  const [sch, cfg] = await Promise.all([api('/api/config/schema'), api('/api/config')]);
  if (sch.status !== 'ok' || cfg.status !== 'ok') {
    root.innerHTML = '<p class="empty">Cannot load configuration.</p>';
    return;
  }
  function getVal(key) {
    return key.split('.').reduce((o, k) => o && o[k] !== undefined ? o[k] : undefined, cfg.data);
  }
  root.innerHTML = `<p style="color:var(--muted);font-size:12px">Editing <code>${esc(cfg.path||'config')}</code>. Saves auto-trigger a server reload (SIGHUP).</p>` +
    sch.data.map(section => `
      <section class="cfg-section">
        <h2>${esc(section.label)}</h2>
        <div class="card">
          <div class="form">
            ${section.fields.map(f => renderField(f, getVal(f.key))).join('')}
          </div>
        </div>
      </section>
    `).join('');
  root.querySelectorAll('[data-cfg-key]').forEach(el => {
    el.onchange = async () => {
      let value;
      if (el.type === 'checkbox') value = el.checked;
      else if (el.type === 'number') value = el.value === '' ? null : Number(el.value);
      else if (el.dataset.cfgType === 'multitext') {
        value = el.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
      } else value = el.value;
      const x = await api('/api/config/key', { method: 'PUT', body: JSON.stringify({ key: el.dataset.cfgKey, value }) });
      toast(x.status==='ok' ? 'Saved · server reloaded' : x.message, x.status==='ok'?'ok':'err');
    };
  });
}

function renderField(f, value) {
  const id = 'cf_' + f.key.replace(/\./g, '_');
  const help = f.help ? `<span class="help">${esc(f.help)}</span>` : '';
  if (f.type === 'bool') {
    return `<div class="row"><label>${esc(f.label)}</label>
      <input type="checkbox" id="${id}" data-cfg-key="${esc(f.key)}" ${value?'checked':''}>${help}</div>`;
  }
  if (f.type === 'select') {
    return `<div class="row"><label>${esc(f.label)}</label>
      <select id="${id}" data-cfg-key="${esc(f.key)}">
        ${(f.options||[]).map(o => `<option value="${esc(o)}" ${o===value?'selected':''}>${esc(o)}</option>`).join('')}
      </select>${help}</div>`;
  }
  if (f.type === 'multitext') {
    const v = Array.isArray(value) ? value.join('\n') : '';
    return `<div class="row"><label>${esc(f.label)}</label>
      <textarea id="${id}" data-cfg-key="${esc(f.key)}" data-cfg-type="multitext">${esc(v)}</textarea>${help}</div>`;
  }
  const t = f.type === 'password' ? 'password' : f.type === 'number' ? 'number' : 'text';
  const v = value === undefined || value === null ? '' : value;
  return `<div class="row"><label>${esc(f.label)}</label>
    <input type="${t}" id="${id}" data-cfg-key="${esc(f.key)}" value="${esc(v)}" ${f.min!==undefined?`min="${f.min}"`:''}>${help}</div>`;
}

/* ── Health view ──────────────────────────────────────────── */
async function viewHealth(root) {
  const r = await api('/api/health');
  if (r.status !== 'ok') { root.innerHTML = '<p class="empty">' + esc(r.message) + '</p>'; return; }
  root.innerHTML = `
    <div class="card" style="margin-bottom:14px">
      <h3>Overall</h3>
      <p>${r.healthy ? '<span class="badge delivered">Healthy</span>' : '<span class="badge failed">Unhealthy</span>'}</p>
    </div>
    ${Object.entries(r.checks || {}).map(([name, val]) => {
      if (Array.isArray(val)) {
        return `<div class="card" style="margin-bottom:10px"><h3>${esc(name)}</h3>
          <table class="tbl">${val.map(x => `<tr>
            <td>${esc(x.name||'-')}:${x.port||''}</td>
            <td>${x.ok ? '<span class="badge delivered">OK</span>' : '<span class="badge failed">Fail</span>'}</td>
            <td class="id">${esc(x.error||'')}</td>
          </tr>`).join('')}</table></div>`;
      }
      return `<div class="card" style="margin-bottom:10px"><h3>${esc(name)}</h3>
        <p>${val.ok ? '<span class="badge delivered">OK</span>' : '<span class="badge failed">Fail</span>'} ${esc(val.detail||'')}</p></div>`;
    }).join('')}
  `;
}
