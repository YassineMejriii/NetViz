(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const el = {
    live: $('live'), liveLabel: $('liveLabel'), iface: $('iface'), mode: $('mode'),
    uptime: $('uptime'), notice: $('notice'), pauseBtn: $('pauseBtn'),
    csvBtn: $('csvBtn'), jsonBtn: $('jsonBtn'), search: $('search'),
    appFilter: $('appFilter'), httpsOnly: $('httpsOnly'), rowCount: $('rowCount'),
    flowRows: $('flowRows'), empty: $('empty'), emptyText: $('emptyText'),
    topDest: $('topDest'), topJa3: $('topJa3'), signals: $('signals'),
    timeline: $('timeline'), graph: $('graph'), tableWrap: $('tableWrap'),
    drawer: $('drawer'), drawerBody: $('drawerBody'), drawerTitle: $('drawerTitle'),
    scrim: $('scrim'), closeDrawer: $('closeDrawer'), copyBtn: $('copyBtn'),
    statPackets: $('statPackets'), statPps: $('statPps'), statBytes: $('statBytes'),
    statBps: $('statBps'), statFlows: $('statFlows'), statHosts: $('statHosts'),
    statHttps: $('statHttps'), statClients: $('statClients'), statSpan: $('statSpan'),
    deviceRows: $('deviceRows'), deviceCount: $('deviceCount'),
    deviceEmpty: $('deviceEmpty'), deviceFilter: $('deviceFilter'),
  };

  const state = {
    flows: new Map(),
    stats: {},
    series: [],
    signals: [],
    devices: [],
    info: {},
    visible: [],
    apps: [],
    appKey: '',
    search: '',
    app: 'all',
    httpsOnly: false,
    device: null,
    sort: { key: 'last', dir: -1 },
    paused: false,
    connected: false,
    selected: null,
    drawerBuilt: null,
    graphModel: { clients: [], dests: [], edges: [] },
    ws: null,
    retry: 0,
  };

  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[ch]));

  const truncate = (text, max) => {
    const str = String(text ?? '');
    return str.length > max ? `${str.slice(0, max - 1)}…` : str;
  };

  const pad = (n, width = 2) => String(n).padStart(width, '0');

  function fmtTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  }

  function fmtClock(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  function fmtDate(ts) {
    if (!ts) return '—';
    const d = new Date(ts * 1000);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  }

  function fmtBytes(n) {
    const value = Number(n) || 0;
    if (value < 1024) return `${Math.round(value)} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let scaled = value / 1024;
    let idx = 0;
    while (scaled >= 1024 && idx < units.length - 1) {
      scaled /= 1024;
      idx += 1;
    }
    const digits = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
    return `${scaled.toFixed(digits)} ${units[idx]}`;
  }

  function fmtNum(n) {
    const value = Number(n) || 0;
    if (value >= 1e6) return `${(value / 1e6).toFixed(1)}M`;
    if (value >= 1e4) return `${Math.round(value / 1e3)}k`;
    if (value >= 1e3) return `${(value / 1e3).toFixed(1)}k`;
    return String(Math.round(value));
  }

  function fmtDur(seconds) {
    const total = Math.max(0, Math.floor(Number(seconds) || 0));
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    if (h > 0) return `${pad(h)}:${pad(m)}:${pad(s)}`;
    if (m > 0) return `${pad(m)}:${pad(s)}`;
    return `${s}s`;
  }

  function hexRgba(hex, alpha) {
    const value = hex.replace('#', '');
    const r = parseInt(value.slice(0, 2), 16);
    const g = parseInt(value.slice(2, 4), 16);
    const b = parseInt(value.slice(4, 6), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }

  const APP_COLOR = {
    HTTPS: '#2fe3ff', HTTP: '#ffc857', DNS: '#43f7a1',
    QUIC: '#9a7cff', TLS: '#ff5cf4', ICMP: '#ff5c72', ICMPv6: '#ff5c72',
  };
  const appColor = (app, alpha = 1) => hexRgba(APP_COLOR[app] || '#5d7f9a', alpha);

  /* ---------------- socket ---------------- */
  function connect() {
    let socket;
    try {
      const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
      socket = new WebSocket(`${scheme}://${location.host}/ws`);
    } catch (err) {
      setTimeout(connect, 1500);
      return;
    }
    state.ws = socket;
    socket.onopen = () => {
      state.connected = true;
      state.retry = 0;
      updateLive();
      socket.send(JSON.stringify({ type: 'hello' }));
      if (state.paused) socket.send(JSON.stringify({ type: 'pause' }));
    };
    socket.onmessage = (event) => {
      if (state.paused) return;
      let message;
      try {
        message = JSON.parse(event.data);
      } catch (err) {
        return;
      }
      ingest(message);
    };
    socket.onclose = () => {
      state.connected = false;
      updateLive();
      const wait = Math.min(5000, 600 * 2 ** state.retry);
      state.retry += 1;
      setTimeout(connect, wait);
    };
    socket.onerror = () => {
      try { socket.close(); } catch (err) { /* already closing */ }
    };
  }

  function ingest(message) {
    if (!message || typeof message !== 'object') return;
    if (message.type === 'snapshot') {
      state.flows.clear();
      for (const flow of message.flows || []) state.flows.set(flow.id, flow);
      state.devices = message.devices || [];
      state.series = message.series || [];
      state.signals = message.signals || [];
      if (message.info) state.info = message.info;
    } else if (message.type === 'tick') {
      for (const flow of message.flows || []) state.flows.set(flow.id, flow);
      for (const id of message.removed || []) state.flows.delete(id);
      if (message.devices) state.devices = message.devices;
      if (message.series) state.series = message.series;
      if (message.signals) state.signals = message.signals;
      if (message.info) state.info = message.info;
    } else {
      return;
    }
    if (message.stats) state.stats = message.stats;
    scheduleRender();
  }

  /* ---------------- render ---------------- */
  let renderTimer = null;
  let lastRender = 0;

  function scheduleRender() {
    if (renderTimer) return;
    const wait = Math.max(0, 180 - (performance.now() - lastRender));
    renderTimer = setTimeout(() => {
      renderTimer = null;
      lastRender = performance.now();
      render();
    }, wait);
  }

  function render() {
    renderInfo();
    renderStats();
    renderDevices();
    renderTable();
    renderSide();
    renderDrawer();
    state.graphModel = buildGraph();
  }

  function renderInfo() {
    const info = state.info || {};
    el.iface.textContent = info.iface || '—';
    el.mode.textContent = info.mode ? String(info.mode).toUpperCase() : '—';
    if (info.notice) {
      el.notice.textContent = info.notice;
      el.notice.classList.remove('hidden');
    } else {
      el.notice.classList.add('hidden');
    }
    if (info.mode === 'demo') {
      el.emptyText.textContent = 'Synthetic traffic is flowing. Filter, sort, or open a row.';
    } else if (info.notice) {
      el.emptyText.textContent = info.notice;
    }
    updateLive();
  }

  function updateLive() {
    if (state.paused) {
      el.live.dataset.state = 'paused';
      el.liveLabel.textContent = 'PAUSED';
    } else if (state.connected) {
      el.live.dataset.state = 'live';
      el.liveLabel.textContent = 'LIVE';
    } else {
      el.live.dataset.state = 'offline';
      el.liveLabel.textContent = 'RECONNECTING';
    }
    el.pauseBtn.classList.toggle('active', state.paused);
    el.pauseBtn.textContent = state.paused ? 'RESUME' : 'PAUSE';
  }

  function renderStats() {
    const s = state.stats || {};
    el.statPackets.textContent = fmtNum(s.packets);
    el.statPps.textContent = `${fmtNum(s.pps)} pps`;
    el.statBytes.textContent = fmtBytes(s.bytes);
    el.statBps.textContent = `${fmtBytes(s.bps)}/s`;
    el.statFlows.textContent = fmtNum(s.flows);
    el.statHosts.textContent = `${fmtNum(s.hosts)} hosts`;
    el.statHttps.textContent = fmtNum(s.https_hosts);
    el.statClients.textContent = fmtNum(s.clients);
    el.statSpan.textContent = `${fmtNum(s.devices)} devices · ${fmtDur(s.span)}`;
    el.uptime.textContent = fmtDur(s.uptime);
    renderAppFilter(s.apps || []);
  }

  function renderAppFilter(apps) {
    const signature = apps.map(([name]) => name).join('\u0000');
    if (signature === state.appKey) {
      const counts = new Map(apps);
      for (const option of el.appFilter.options) {
        if (option.value === 'all') continue;
        const count = counts.get(option.value);
        if (count !== undefined) option.textContent = `${option.value} · ${fmtNum(count)}`;
      }
      return;
    }
    state.appKey = signature;
    state.apps = apps;
    const current = state.app;
    const options = ['<option value="all">all apps</option>'];
    for (const [name, count] of apps) {
      options.push(`<option value="${esc(name)}">${esc(name)} · ${fmtNum(count)}</option>`);
    }
    el.appFilter.innerHTML = options.join('');
    if (current !== 'all' && !apps.some(([name]) => name === current)) {
      state.app = 'all';
      el.appFilter.value = 'all';
    } else {
      el.appFilter.value = state.app;
    }
  }

  function renderDevices() {
    const devices = state.devices || [];
    el.deviceCount.textContent = `${devices.length} ${devices.length === 1 ? 'device' : 'devices'}`;
    el.deviceEmpty.classList.toggle('hidden', devices.length > 0);
    const active = state.device ? devices.find((d) => d.key === state.device) : null;
    el.deviceFilter.classList.toggle('hidden', !state.device);
    if (state.device) {
      const label = active ? (active.hostname || active.mac || active.ip) : state.device;
      el.deviceFilter.textContent = `CLEAR · ${truncate(label, 18)}`;
    }
    el.deviceRows.innerHTML = devices.slice(0, 80).map((dev) => {
      const name = dev.hostname || dev.mac || dev.ip;
      const sub = [dev.mac, dev.ip].filter(Boolean).join(' · ');
      const apps = (dev.apps || []).map(([app, count]) =>
        `<span class="badge" data-app="${esc(app)}" title="${count} packets">${esc(app)}</span>`).join(' ');
      const selected = dev.key === state.device ? ' class="selected"' : '';
      return `<tr data-device="${esc(dev.key)}"${selected}>
        <td class="device-id">
          <span class="dev-name" title="${esc(name)}">${esc(truncate(name, 34))}</span>
          <span class="dev-sub">${esc(sub)}${dev.hostname_source ? ` · ${esc(dev.hostname_source)}` : ''}</span>
        </td>
        <td class="device-vendor" title="${esc(dev.vendor || '')}">${esc(truncate(dev.vendor || '—', 28))}</td>
        <td class="time">${fmtTime(dev.first)}</td>
        <td class="time">${fmtTime(dev.last)}</td>
        <td class="num">${fmtNum(dev.destinations)}</td>
        <td class="num">${fmtBytes(dev.bytes)}</td>
        <td class="device-apps">${apps || '<span class="hint">—</span>'}</td>
      </tr>`;
    }).join('');
  }

  function visibleFlows() {
    const needle = state.search.trim().toLowerCase();
    const out = [];
    for (const flow of state.flows.values()) {
      if (state.device && flow.device !== state.device) continue;
      if (state.httpsOnly && flow.app !== 'HTTPS') continue;
      if (state.app !== 'all' && flow.app !== state.app) continue;
      if (needle) {
        const hay = `${flow.host || ''} ${flow.sni || ''} ${flow.dns_qname || ''} ` +
          `${flow.client} ${flow.server} ${flow.server_port} ${flow.cport} ` +
          `${flow.ja3 || ''} ${flow.app} ${flow.http_path || ''} ` +
          `${flow.client_vendor || ''} ${flow.device_hostname || ''} ${flow.device || ''}`.toLowerCase();
        if (!hay.includes(needle)) continue;
      }
      out.push(flow);
    }
    const { key, dir } = state.sort;
    out.sort((a, b) => {
      const av = key === 'last' ? a.last : key === 'packets' ? a.packets : a.bytes;
      const bv = key === 'last' ? b.last : key === 'packets' ? b.packets : b.bytes;
      return av === bv ? 0 : av < bv ? -dir : dir;
    });
    return out;
  }

  function detailText(flow) {
    const bits = [];
    if (flow.http_method) bits.push(`${flow.http_method} ${truncate(flow.http_path || '', 26)}`);
    if (flow.dns_qname) bits.push(flow.dns_qname);
    if (flow.tls_version) bits.push(flow.tls_version);
    if (flow.alpn) bits.push(flow.alpn);
    if (flow.ja3) bits.push(flow.ja3.slice(0, 8));
    if (!bits.length && flow.flags) bits.push(flow.flags);
    const dir = `↑${fmtNum(flow.c2s_pkts)} ↓${fmtNum(flow.s2c_pkts)}`;
    return `${dir}${bits.length ? ` · ${bits.join(' · ')}` : ''}`;
  }

  function rowHTML(flow) {
    const scope = flow.scope && flow.scope !== 'public'
      ? `<span class="scope ${esc(flow.scope)}">${esc(flow.scope)}</span>` : '';
    const source = flow.host && flow.host_source
      ? `<span class="src">${esc(flow.host_source)}</span>` : '';
    const extra = flow.hosts && flow.hosts.length > 1
      ? `<span class="more">+${flow.hosts.length - 1}</span>` : '';
    const host = flow.host
      ? `<span class="host" title="${esc(flow.host)}">${esc(truncate(flow.host, 44))}</span>${source}${extra}`
      : '<span class="host none">—</span>';
    const selected = flow.id === state.selected ? ' class="selected"' : '';
    return `<tr data-id="${flow.id}"${selected}>
      <td class="time">${fmtTime(flow.last)}</td>
      <td class="addr"><span class="ip">${esc(flow.client)}</span><span class="port">:${flow.cport || '—'}</span></td>
      <td class="addr"><span class="ip">${esc(flow.server)}</span><span class="port">:${flow.server_port || '—'}</span>${scope}</td>
      <td class="hostcell">${host}</td>
      <td><span class="badge" data-app="${esc(flow.app)}">${esc(flow.app)}</span></td>
      <td class="num">${fmtNum(flow.packets)}</td>
      <td class="num">${fmtBytes(flow.bytes)}</td>
      <td class="detail" title="${esc(detailText(flow))}">${esc(detailText(flow))}</td>
    </tr>`;
  }

  function renderTable() {
    const rows = visibleFlows();
    state.visible = rows;
    el.rowCount.textContent = `${rows.length} ${rows.length === 1 ? 'row' : 'rows'}`;
    el.empty.classList.toggle('hidden', rows.length > 0);
    const slice = rows.slice(0, 300);
    el.flowRows.innerHTML = slice.map(rowHTML).join('');
    document.querySelectorAll('thead th.sortable').forEach((th) => {
      const key = th.dataset.sort;
      th.classList.toggle('sorted-asc', key === state.sort.key && state.sort.dir === 1);
      th.classList.toggle('sorted-desc', key === state.sort.key && state.sort.dir === -1);
    });
  }

  function renderSide() {
    const s = state.stats || {};
    const dests = s.top_dest || [];
    const maxBytes = dests.reduce((max, d) => Math.max(max, d.bytes), 1);
    el.topDest.innerHTML = dests.length
      ? dests.map((d, i) => `<li>
          <span class="n">${pad(i + 1)}</span>
          <span class="label" title="${esc(d.label)}"><b>${esc(truncate(d.label, 26))}</b> <span class="hint">${esc(d.ip)}</span></span>
          <span class="val">${fmtBytes(d.bytes)}</span>
          <span class="bar" style="transform:scaleX(${Math.max(0.02, d.bytes / maxBytes).toFixed(3)})"></span>
        </li>`).join('')
      : '<li class="empty-line">no destinations yet</li>';

    const ja3s = s.top_ja3 || [];
    const maxJa3 = ja3s.reduce((max, d) => Math.max(max, d.flows), 1);
    el.topJa3.innerHTML = ja3s.length
      ? ja3s.map((d, i) => `<li>
          <span class="n">${pad(i + 1)}</span>
          <span class="label" title="${esc(d.ja3)}"><b>${esc(d.ja3.slice(0, 16))}</b> <span class="hint">${d.flows} flows</span></span>
          <span class="val">${fmtBytes(d.bytes)}</span>
          <span class="bar" style="transform:scaleX(${Math.max(0.02, d.flows / maxJa3).toFixed(3)});background:linear-gradient(90deg,rgba(255,92,244,.55),rgba(255,92,244,.05))"></span>
        </li>`).join('')
      : '<li class="empty-line">no TLS handshakes yet</li>';

    const signals = (state.signals || []).slice(-14).reverse();
    el.signals.innerHTML = signals.length
      ? signals.map((sig) => `<li>
          <span class="t">${fmtClock(sig.ts)}</span>
          <div>
            <div class="h">${esc(sig.host || sig.ip)}</div>
            <div class="m">${esc(sig.app || '')} ${esc(sig.ip || '')}${sig.ja3 ? ` · ${esc(sig.ja3.slice(0, 8))}` : ''}</div>
          </div>
        </li>`).join('')
      : '<li class="empty-line">watching for new hosts</li>';
  }

  /* ---------------- drawer ---------------- */
  function openDrawer(id) {
    state.selected = id;
    state.drawerBuilt = null;
    el.drawer.classList.add('open');
    el.scrim.classList.add('open');
    el.drawer.setAttribute('aria-hidden', 'false');
    renderDrawer();
  }

  function closeDrawer() {
    state.selected = null;
    state.drawerBuilt = null;
    el.drawer.classList.remove('open');
    el.scrim.classList.remove('open');
    el.drawer.setAttribute('aria-hidden', 'true');
    renderTable();
  }

  function buildDrawer(flow) {
    const kv = (label, value, cls = '') =>
      `<dt>${esc(label)}</dt><dd class="${cls}" data-f="${label}">${value}</dd>`;
    const hosts = (flow.hosts || []).map(([host, count]) =>
      `${esc(host)} <span class="hint">×${count}</span>`).join('<br>') || '—';
    el.drawerTitle.textContent = flow.host || flow.server;
    const split = `<span>sent <b>${fmtBytes(flow.c2s_bytes)}</b> / ${fmtNum(flow.c2s_pkts)} pkts</span>` +
      `<span>recv <b>${fmtBytes(flow.s2c_bytes)}</b> / ${fmtNum(flow.s2c_pkts)} pkts</span>`;
    el.drawerBody.innerHTML = `
      <div class="section-label">Connection</div>
      <dl class="kv">
        <dt>Client</dt><dd>${esc(flow.client)}<span class="hint"> :${flow.cport || '—'}</span></dd>
        <dt>Destination</dt><dd>${esc(flow.server)}<span class="hint"> :${flow.server_port || '—'}</span></dd>
        <dt>Protocol</dt><dd>${esc(flow.proto)} · <span class="hint">${esc(flow.scope)}</span></dd>
        <dt>Application</dt><dd>${esc(flow.app)}</dd>
        <dt>First seen</dt><dd>${fmtDate(flow.first)}</dd>
        <dt>Last seen</dt><dd>${fmtDate(flow.last)}</dd>
        <dt>Duration</dt><dd data-f="duration">${fmtDur(flow.last - flow.first)}</dd>
        <dt>Packets</dt><dd data-f="packets">${fmtNum(flow.packets)}</dd>
        <dt>Bytes</dt><dd data-f="bytes">${fmtBytes(flow.bytes)}</dd>
        <dt>Direction</dt><dd class="split" data-f="split">${split}</dd>
      </dl>
      <div class="section-label">Application metadata</div>
      <dl class="kv">
        <dt>Host</dt><dd data-f="host">${esc(flow.host || '—')}</dd>
        <dt>Host source</dt><dd class="dim">${esc(flow.host_source || '—')}</dd>
        <dt>SNI</dt><dd>${esc(flow.sni || '—')}</dd>
        <dt>DNS query</dt><dd>${esc(flow.dns_qname || '—')}</dd>
        <dt>HTTP request</dt><dd>${flow.http_method ? `${esc(flow.http_method)} ${esc(flow.http_path || '')}` : '—'}</dd>
        <dt>TLS version</dt><dd>${esc(flow.tls_version || '—')}</dd>
        <dt>ALPN</dt><dd>${esc(flow.alpn || '—')}</dd>
        <dt>JA3</dt><dd>${esc(flow.ja3 || '—')}</dd>
        <dt>Hosts on flow</dt><dd data-f="hosts">${hosts}</dd>
      </dl>
      <div class="section-label">Link</div>
      <dl class="kv">
        <dt>Client MAC</dt><dd>${esc(flow.client_mac || '—')}</dd>
        <dt>Client vendor</dt><dd>${esc(flow.client_vendor || '—')}</dd>
        <dt>Server MAC</dt><dd>${esc(flow.server_mac || '—')}</dd>
        <dt>Server vendor</dt><dd>${esc(flow.server_vendor || '—')}</dd>
        <dt>Device</dt><dd>${esc(flow.device_hostname || flow.device || '—')}</dd>
        <dt>TTL / hop</dt><dd>${esc(flow.ttl || '—')}</dd>
        <dt>Last flags</dt><dd data-f="flags">${esc(flow.flags || '—')}</dd>
        <dt>Flow id</dt><dd class="dim">${esc(flow.id)}</dd>
      </dl>
      <div class="section-label">JSON</div>
      <pre class="json" id="drawerJson">${esc(JSON.stringify(flow, null, 2))}</pre>`;
    state.drawerBuilt = flow.id;
  }

  function renderDrawer() {
    if (!state.selected) return;
    const flow = state.flows.get(state.selected);
    if (!flow) {
      closeDrawer();
      return;
    }
    if (state.drawerBuilt !== flow.id) {
      buildDrawer(flow);
      return;
    }
    const set = (field, html) => {
      const node = el.drawerBody.querySelector(`[data-f="${field}"]`);
      if (node) node.innerHTML = html;
    };
    set('duration', fmtDur(flow.last - flow.first));
    set('packets', fmtNum(flow.packets));
    set('bytes', fmtBytes(flow.bytes));
    set('host', esc(flow.host || '—'));
    set('flags', esc(flow.flags || '—'));
    set('split', `<span>sent <b>${fmtBytes(flow.c2s_bytes)}</b> / ${fmtNum(flow.c2s_pkts)} pkts</span>` +
      `<span>recv <b>${fmtBytes(flow.s2c_bytes)}</b> / ${fmtNum(flow.s2c_pkts)} pkts</span>`);
    set('hosts', (flow.hosts || []).map(([host, count]) =>
      `${esc(host)} <span class="hint">×${count}</span>`).join('<br>') || '—');
  }

  /* ---------------- graph model ---------------- */
  function hashString(text) {
    let hash = 0;
    for (let i = 0; i < text.length; i += 1) {
      hash = ((hash << 5) - hash + text.charCodeAt(i)) | 0;
    }
    return Math.abs(hash);
  }

  function destKey(flow) {
    return ['DNS', 'mDNS'].includes(flow.app) ? flow.server : (flow.host || flow.server);
  }

  function buildGraph() {
    const flows = [...state.flows.values()];
    const destAgg = new Map();
    const clientAgg = new Map();
    for (const flow of flows) {
      const key = destKey(flow);
      let dest = destAgg.get(key);
      if (!dest) {
        dest = { key, label: key, ip: flow.server, bytes: 0, app: flow.app };
        destAgg.set(key, dest);
      }
      dest.bytes += flow.bytes;
      if (['HTTPS', 'HTTP', 'DNS', 'QUIC'].includes(flow.app)) dest.app = flow.app;
      clientAgg.set(flow.client, (clientAgg.get(flow.client) || 0) + flow.bytes);
    }
    const clients = [...clientAgg.entries()]
      .sort((a, b) => b[1] - a[1]).slice(0, 5)
      .map(([ip, bytes]) => ({ key: ip, label: ip, bytes }));
    const dests = [...destAgg.values()]
      .sort((a, b) => b.bytes - a.bytes).slice(0, 10);
    const clientSet = new Set(clients.map((c) => c.key));
    const destSet = new Set(dests.map((d) => d.key));
    const edgeMap = new Map();
    for (const flow of flows) {
      if (!clientSet.has(flow.client)) continue;
      const dkey = destKey(flow);
      if (!destSet.has(dkey)) continue;
      const key = `${flow.client}\u0000${dkey}`;
      let edge = edgeMap.get(key);
      if (!edge) {
        edge = { from: flow.client, to: dkey, bytes: 0, app: flow.app, last: flow.last };
        edgeMap.set(key, edge);
      }
      edge.bytes += flow.bytes;
      if (flow.last >= edge.last) {
        edge.last = flow.last;
        edge.app = flow.app;
      }
    }
    return { clients, dests, edges: [...edgeMap.values()].slice(0, 80) };
  }

  /* ---------------- canvas ---------------- */
  function fitCanvas(canvas) {
    if (!canvas) return null;
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    if (!width || !height) return null;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    if (canvas.width !== Math.round(width * dpr) || canvas.height !== Math.round(height * dpr)) {
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
    }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx, width, height };
  }

  function drawTimeline() {
    const fitted = fitCanvas(el.timeline);
    if (!fitted) return;
    const { ctx, width, height } = fitted;
    ctx.clearRect(0, 0, width, height);
    const padL = 8, padR = 10, padT = 10, padB = 16;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;

    ctx.strokeStyle = 'rgba(34, 53, 69, 0.5)';
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 4]);
    for (let i = 0; i <= 4; i += 1) {
      const y = padT + (plotH * i) / 4;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(padL + plotW, y);
      ctx.stroke();
    }
    ctx.setLineDash([]);

    ctx.font = '9px ui-monospace, SFMono-Regular, Menlo, monospace';
    ctx.fillStyle = '#4a6074';
    ctx.textBaseline = 'top';
    ctx.fillText('-3m', padL, padT + plotH + 3);
    ctx.textAlign = 'right';
    ctx.fillText('now', padL + plotW, padT + plotH + 3);
    ctx.textAlign = 'left';

    const series = state.series || [];
    if (series.length < 2) {
      ctx.fillStyle = '#4a6074';
      ctx.fillText('waiting for samples', padL + 4, padT + 4);
      return;
    }

    const buckets = new Map(series.map(([sec, packets, bytes]) => [sec, [packets, bytes]]));
    const end = series[series.length - 1][0];
    const start = end - 179;
    const points = [];
    let maxBytes = 1;
    let maxPkts = 1;
    for (let sec = start; sec <= end; sec += 1) {
      const bucket = buckets.get(sec);
      const packets = bucket ? bucket[0] : 0;
      const bytes = bucket ? bucket[1] : 0;
      maxBytes = Math.max(maxBytes, bytes);
      maxPkts = Math.max(maxPkts, packets);
      points.push([packets, bytes]);
    }
    const xAt = (i) => padL + (i / (points.length - 1)) * plotW;
    const yBytes = (value) => padT + plotH - (value / maxBytes) * plotH;
    const yPkts = (value) => padT + plotH - (value / maxPkts) * plotH * 0.82;

    const grad = ctx.createLinearGradient(0, padT, 0, padT + plotH);
    grad.addColorStop(0, 'rgba(47, 227, 255, 0.28)');
    grad.addColorStop(1, 'rgba(47, 227, 255, 0.01)');
    ctx.beginPath();
    ctx.moveTo(xAt(0), padT + plotH);
    points.forEach(([, bytes], i) => ctx.lineTo(xAt(i), yBytes(bytes)));
    ctx.lineTo(xAt(points.length - 1), padT + plotH);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    points.forEach(([, bytes], i) => {
      const x = xAt(i);
      const y = yBytes(bytes);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = 'rgba(47, 227, 255, 0.85)';
    ctx.lineWidth = 1.3;
    ctx.stroke();

    ctx.beginPath();
    points.forEach(([packets], i) => {
      const x = xAt(i);
      const y = yPkts(packets);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = 'rgba(67, 247, 161, 0.75)';
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 3]);
    ctx.stroke();
    ctx.setLineDash([]);

    ctx.textAlign = 'right';
    ctx.fillStyle = '#5d7f9a';
    ctx.fillText(`${fmtBytes(maxBytes)}/s`, padL + plotW, padT + 1);
    ctx.textAlign = 'left';
  }

  function bezierPoint(a, c1, c2, b, t) {
    const mt = 1 - t;
    const x = mt ** 3 * a.x + 3 * mt ** 2 * t * c1.x + 3 * mt * t ** 2 * c2.x + t ** 3 * b.x;
    const y = mt ** 3 * a.y + 3 * mt ** 2 * t * c1.y + 3 * mt * t ** 2 * c2.y + t ** 3 * b.y;
    return { x, y };
  }

  function drawGraph(timeMs) {
    const fitted = fitCanvas(el.graph);
    if (!fitted) return;
    const { ctx, width, height } = fitted;
    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = 'rgba(34, 53, 69, 0.35)';
    ctx.setLineDash([2, 6]);
    ctx.beginPath();
    ctx.moveTo(width / 2, 10);
    ctx.lineTo(width / 2, height - 10);
    ctx.stroke();
    ctx.setLineDash([]);

    const model = state.graphModel;
    if (!model || !model.dests.length) {
      ctx.fillStyle = '#4a6074';
      ctx.font = '9px ui-monospace, SFMono-Regular, Menlo, monospace';
      ctx.fillText('no destinations yet', 12, 16);
      return;
    }

    const padY = 20;
    const colL = Math.min(126, width * 0.24);
    const colR = width - Math.min(150, width * 0.3);
    const posClient = new Map();
    model.clients.forEach((client, i) => {
      const y = padY + ((i + 1) / (model.clients.length + 1)) * (height - 2 * padY);
      posClient.set(client.key, { x: colL, y, data: client });
    });
    const posDest = new Map();
    model.dests.forEach((dest, i) => {
      const y = padY + ((i + 1) / (model.dests.length + 1)) * (height - 2 * padY);
      posDest.set(dest.key, { x: colR, y, data: dest });
    });

    const maxEdge = model.edges.reduce((max, e) => Math.max(max, e.bytes), 1);
    for (const edge of model.edges) {
      const a = posClient.get(edge.from);
      const b = posDest.get(edge.to);
      if (!a || !b) continue;
      const weight = Math.min(1, Math.log10(1 + edge.bytes) / 6);
      const alpha = 0.08 + (edge.bytes / maxEdge) * 0.34;
      const midX = (a.x + b.x) / 2;
      const dy = b.y - a.y;
      const c1 = { x: midX, y: a.y + dy * 0.08 };
      const c2 = { x: midX, y: b.y - dy * 0.08 };
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.bezierCurveTo(c1.x, c1.y, c2.x, c2.y, b.x, b.y);
      ctx.strokeStyle = appColor(edge.app, alpha);
      ctx.lineWidth = 0.6 + weight * 1.8;
      ctx.stroke();

      const speed = 0.06 + weight * 0.22;
      const phase = (timeMs / 1000) * speed + (hashString(`${edge.from}${edge.to}`) % 1000) / 1000;
      const t = phase % 1;
      const point = bezierPoint(a, c1, c2, b, t);
      ctx.beginPath();
      ctx.arc(point.x, point.y, 1.1 + weight * 1.7, 0, Math.PI * 2);
      ctx.fillStyle = appColor(edge.app, 0.35 + weight * 0.6);
      ctx.fill();
    }

    ctx.font = '9px ui-monospace, SFMono-Regular, Menlo, monospace';
    ctx.textBaseline = 'middle';
    for (const [, node] of posClient) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, 3, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(207, 227, 245, 0.9)';
      ctx.fill();
      ctx.strokeStyle = 'rgba(207, 227, 245, 0.18)';
      ctx.lineWidth = 5;
      ctx.stroke();
      ctx.fillStyle = '#7890a5';
      ctx.textAlign = 'left';
      ctx.fillText(truncate(node.data.label, 15), node.x + 10, node.y);
    }
    for (const [, node] of posDest) {
      const radius = 2.5 + Math.min(4, Math.log10(1 + node.data.bytes) / 1.4);
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = appColor(node.data.app, 0.9);
      ctx.fill();
      ctx.shadowColor = appColor(node.data.app, 0.8);
      ctx.shadowBlur = 10;
      ctx.fill();
      ctx.shadowBlur = 0;
      ctx.fillStyle = '#cfe3f5';
      ctx.textAlign = 'left';
      ctx.fillText(truncate(node.data.label, 22), node.x + 10, node.y);
    }
  }

  function vizLoop(timeMs) {
    drawGraph(timeMs);
    requestAnimationFrame(vizLoop);
  }

  /* ---------------- export ---------------- */
  function download(name, type, text) {
    const blob = new Blob([text], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  function stamp() {
    const d = new Date();
    return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-` +
      `${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
  }

  const CSV_COLUMNS = [
    'first', 'last', 'client', 'cport', 'server', 'server_port', 'proto', 'app',
    'host', 'host_source', 'sni', 'dns_qname', 'http_method', 'http_path',
    'tls_version', 'alpn', 'ja3', 'packets', 'bytes', 'c2s_pkts', 's2c_pkts',
    'c2s_bytes', 's2c_bytes', 'ttl', 'flags', 'client_mac', 'server_mac',
    'client_vendor', 'server_vendor', 'device', 'device_hostname',
    'scope', 'id',
  ];

  function exportRows() {
    return state.visible.length ? state.visible : [...state.flows.values()];
  }

  function exportCsv() {
    const rows = exportRows();
    const lines = [CSV_COLUMNS.join(',')];
    for (const flow of rows) {
      const values = CSV_COLUMNS.map((column) => {
        let value = flow[column];
        if (column === 'first' || column === 'last') {
          value = value ? new Date(value * 1000).toISOString() : '';
        }
        if (value === null || value === undefined) value = '';
        return `"${String(value).replace(/"/g, '""')}"`;
      });
      lines.push(values.join(','));
    }
    download(`netviz-${stamp()}.csv`, 'text/csv;charset=utf-8', lines.join('\n'));
  }

  function exportJson() {
    download(`netviz-${stamp()}.json`, 'application/json',
      JSON.stringify(exportRows(), null, 2));
  }

  /* ---------------- events ---------------- */
  el.search.addEventListener('input', () => {
    state.search = el.search.value;
    scheduleRender();
  });
  el.appFilter.addEventListener('change', () => {
    state.app = el.appFilter.value;
    scheduleRender();
  });
  el.httpsOnly.addEventListener('change', () => {
    state.httpsOnly = el.httpsOnly.checked;
    scheduleRender();
  });
  document.querySelectorAll('thead th.sortable').forEach((th) => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      if (state.sort.key === key) {
        state.sort.dir *= -1;
      } else {
        state.sort = { key, dir: -1 };
      }
      scheduleRender();
    });
  });
  el.flowRows.addEventListener('click', (event) => {
    const row = event.target.closest('tr[data-id]');
    if (!row) return;
    openDrawer(row.dataset.id);
    renderTable();
  });
  el.deviceRows.addEventListener('click', (event) => {
    const row = event.target.closest('tr[data-device]');
    if (!row) return;
    const key = row.dataset.device;
    state.device = state.device === key ? null : key;
    scheduleRender();
  });
  el.deviceFilter.addEventListener('click', () => {
    state.device = null;
    scheduleRender();
  });
  el.pauseBtn.addEventListener('click', () => {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return;
    if (state.paused) {
      state.ws.send(JSON.stringify({ type: 'resume' }));
      state.paused = false;
    } else {
      state.ws.send(JSON.stringify({ type: 'pause' }));
      state.paused = true;
    }
    updateLive();
  });
  el.csvBtn.addEventListener('click', exportCsv);
  el.jsonBtn.addEventListener('click', exportJson);
  el.closeDrawer.addEventListener('click', closeDrawer);
  el.scrim.addEventListener('click', closeDrawer);
  el.copyBtn.addEventListener('click', async () => {
    const flow = state.selected ? state.flows.get(state.selected) : null;
    if (!flow) return;
    const text = JSON.stringify(flow, null, 2);
    try {
      await navigator.clipboard.writeText(text);
      el.copyBtn.textContent = 'COPIED';
      setTimeout(() => { el.copyBtn.textContent = 'COPY JSON'; }, 1200);
    } catch (err) {
      const area = document.createElement('textarea');
      area.value = text;
      document.body.appendChild(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeDrawer();
    if (event.key === '/' && document.activeElement !== el.search) {
      event.preventDefault();
      el.search.focus();
    }
  });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && state.ws && state.ws.readyState === WebSocket.OPEN && !state.paused) {
      state.ws.send(JSON.stringify({ type: 'snapshot' }));
    }
  });
  window.addEventListener('resize', () => {
    drawTimeline();
  });

  connect();
  setInterval(drawTimeline, 300);
  requestAnimationFrame(vizLoop);
})();
