// runflow.js — the live flow view of one run: agent boxes, the edges between them, and
// animated packets carrying each request and reply as the gateway records it. Driven by
// polling /runs/{id}/state (204 while nothing changed); new rows are queued and played in
// order, so a burst of events still reads as a sequence. A finished run can be replayed.
(() => {
  const SVG = 'http://www.w3.org/2000/svg';
  const NODE_W = 176, NODE_H = 72, GAP = 72, TOP = 150, YOU_Y = 28, PAD = 28;
  const PACKET_MS = 1100, STEP_GAP_MS = 350;

  function el(tag, attrs, parent) {
    const n = document.createElementNS(SVG, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  function trunc(s, n) { s = (s || '').replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1) + '…' : s; }

  class Flow {
    constructor(root) {
      this.root = root;
      this.url = root.dataset.runFlow;
      this.svg = root.querySelector('[data-flow-svg]');
      this.feed = root.querySelector('[data-flow-feed]');
      this.statusEl = root.querySelector('[data-flow-status]');
      this.noteEl = root.querySelector('[data-flow-note]');
      this.sig = '';
      this.state = null;
      this.played = 0;       // rows already animated
      this.queue = [];       // rows waiting to animate
      this.playing = false;
      this.nodes = [];       // {g, box, name, state, data, x, y}
      this.edges = new Map(); // "from-to" → path
      this.open = new Map();  // target index → open call count
      root.querySelector('[data-flow-replay]')?.addEventListener('click', () => this.replay());
      this.stage = root.querySelector('[data-flow-stage]');
      this.view = { x: 0, y: 0, w: 720, h: 360 }; // the viewBox: pan by moving x/y, zoom by scaling w/h
      this.content = { w: 720, h: 360 };
      this.installPanZoom();
      this.poll();
      this.timer = setInterval(() => this.poll(), 1000);
      const stop = () => { if (!document.body.contains(root)) clearInterval(this.timer); };
      document.body.addEventListener('htmx:afterSwap', stop);
    }

    async poll() {
      if (!document.body.contains(this.root)) { clearInterval(this.timer); return; }
      try {
        const res = await fetch(this.url + '?known=' + encodeURIComponent(this.sig), { headers: { Accept: 'application/json' } });
        if (res.status === 204) return;
        if (!res.ok) { this.noteEl.textContent = 'cannot reach the gateway'; return; }
        const state = await res.json();
        this.sig = state.sig;
        this.apply(state);
      } catch (e) { this.noteEl.textContent = 'cannot reach the gateway'; }
    }

    apply(state) {
      const fresh = !this.state || this.state.participants.length !== state.participants.length;
      this.state = state;
      if (fresh) this.layout();
      this.statusEl.textContent = state.status;
      this.statusEl.className = 'pill ' + ({ ok: 'bg-ok-soft text-ok', warn: 'bg-warn-soft text-warn', bad: 'bg-bad-soft text-bad' }[state.status_tone] || 'bg-panel text-ink-soft');
      for (let i = this.played; i < state.rows.length; i++) this.queue.push({ index: i, row: state.rows[i] });
      this.played = state.rows.length;
      // an ask that was pending and is now settled stops pulsing without a new row
      for (const n of this.nodes) if (n.state === 'waiting' && !state.rows.some((r) => r.kind === 'ask' && r.pending && r.from === n.index)) this.setState(n.index, this.open.get(n.index) ? 'working' : 'idle');
      this.noteEl.textContent = state.rows.length + ' steps · live';
      this.drain();
    }

    // --- pan and zoom: the SVG fills the stage; the viewBox is the camera ---
    installPanZoom() {
      const svg = this.svg;
      svg.addEventListener('wheel', (e) => {
        e.preventDefault();
        const factor = e.deltaY < 0 ? 0.9 : 1.1;
        const p = this.toSVG(e.clientX, e.clientY);
        this.zoomAt(factor, p);
      }, { passive: false });
      let drag = null;
      svg.addEventListener('pointerdown', (e) => {
        if (e.button !== 0) return;
        drag = { x: e.clientX, y: e.clientY, vx: this.view.x, vy: this.view.y };
        svg.setPointerCapture(e.pointerId);
        svg.classList.add('is-dragging');
      });
      svg.addEventListener('pointermove', (e) => {
        if (!drag) return;
        const scale = this.view.w / svg.clientWidth;
        this.view.x = drag.vx - (e.clientX - drag.x) * scale;
        this.view.y = drag.vy - (e.clientY - drag.y) * scale;
        this.applyView();
      });
      const end = (e) => { if (drag) { drag = null; svg.classList.remove('is-dragging'); } };
      svg.addEventListener('pointerup', end); svg.addEventListener('pointercancel', end);
      this.root.querySelectorAll('[data-flow-zoom]').forEach((b) => b.addEventListener('click', () => {
        const mode = b.dataset.flowZoom;
        if (mode === 'fit') return this.fit();
        const c = { x: this.view.x + this.view.w / 2, y: this.view.y + this.view.h / 2 };
        this.zoomAt(mode === 'in' ? 0.8 : 1.25, c);
      }));
      new ResizeObserver(() => this.applyView()).observe(this.stage);
    }
    toSVG(cx, cy) {
      const r = this.svg.getBoundingClientRect();
      return { x: this.view.x + (cx - r.left) / r.width * this.view.w, y: this.view.y + (cy - r.top) / r.height * this.view.h };
    }
    zoomAt(factor, p) {
      const w = Math.max(200, Math.min(this.content.w * 4, this.view.w * factor));
      const ratio = w / this.view.w;
      this.view.x = p.x - (p.x - this.view.x) * ratio;
      this.view.y = p.y - (p.y - this.view.y) * ratio;
      this.view.w = w;
      this.applyView();
    }
    fit() {
      const aspect = this.stage.clientWidth / Math.max(1, this.stage.clientHeight);
      let w = this.content.w, h = w / aspect;
      if (h < this.content.h) { h = this.content.h; w = h * aspect; }
      this.view = { x: (this.content.w - w) / 2, y: (this.content.h - h) / 2, w, h };
      this.applyView();
    }
    applyView() {
      const aspect = this.stage.clientWidth / Math.max(1, this.stage.clientHeight);
      this.view.h = this.view.w / aspect;
      this.svg.setAttribute('viewBox', `${this.view.x} ${this.view.y} ${this.view.w} ${this.view.h}`);
    }

    layout() {
      this.svg.innerHTML = '';
      this.nodes = []; this.edges.clear(); this.open.clear();
      const ps = this.state.participants;
      const row = ps.map((p, i) => i).filter((i) => ps[i].kind !== 'you');
      const width = Math.max(720, PAD * 2 + row.length * NODE_W + (row.length - 1) * GAP);
      const height = TOP + NODE_H + 120;
      this.content = { w: width, h: height };
      this.fit();
      const defs = el('defs', {}, this.svg);
      const marker = el('marker', { id: 'flow-arrow', viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: 'auto' }, defs);
      el('path', { d: 'M0 0L10 5 0 10z', fill: 'currentColor' }, marker);
      this.edgeLayer = el('g', { class: 'flow-edges' }, this.svg);
      this.nodeLayer = el('g', { class: 'flow-nodes' }, this.svg);
      this.packetLayer = el('g', { class: 'flow-packets' }, this.svg);
      ps.forEach((p, i) => {
        const pos = p.kind === 'you'
          ? { x: width / 2 - NODE_W / 2, y: YOU_Y }
          : { x: PAD + row.indexOf(i) * (NODE_W + GAP), y: TOP };
        this.nodes[i] = this.drawNode(i, p, pos.x, pos.y);
      });
    }

    drawNode(index, p, x, y) {
      const g = el('g', { class: `flow-node flow-kind-${p.kind}`, transform: `translate(${x} ${y})` }, this.nodeLayer);
      const box = el('rect', { width: NODE_W, height: NODE_H, rx: 12 }, g);
      el('text', { x: 14, y: 26, class: 'flow-node-name' }, g).textContent = p.name;
      el('text', { x: 14, y: 44, class: 'flow-node-kind' }, g).textContent = p.kind === 'you' ? 'operator' : p.kind === 'harness' ? 'client · key' : 'agent · target';
      const state = el('text', { x: NODE_W - 12, y: 26, 'text-anchor': 'end', class: 'flow-node-state' }, g);
      state.textContent = 'idle';
      const data = el('text', { x: 14, y: 62, class: 'flow-node-data' }, g);
      const node = { index, g, box, state: 'idle', stateEl: state, data, x, y, w: NODE_W, h: NODE_H, kind: p.kind };
      return node;
    }

    center(n) { return { x: n.x + n.w / 2, y: n.y + n.h / 2 }; }

    // edgePath draws from a to b: nodes on the same row arc above (forward) or below (back);
    // anything touching "you" is a straight dashed line from the box tops.
    edgePath(a, b, kind) {
      const A = this.nodes[a], B = this.nodes[b];
      if (A.kind === 'you' || B.kind === 'you') {
        const from = A.kind === 'you' ? { x: A.x + A.w / 2, y: A.y + A.h } : { x: A.x + A.w / 2, y: A.y };
        const to = B.kind === 'you' ? { x: B.x + B.w / 2, y: B.y + B.h } : { x: B.x + B.w / 2, y: B.y };
        return `M${from.x} ${from.y} L${to.x} ${to.y}`;
      }
      const forward = a < b;
      const y = forward ? A.y : A.y + A.h;
      const x1 = A.x + A.w / 2 + (forward ? 20 : -20), x2 = B.x + B.w / 2 + (forward ? -20 : 20);
      const lift = Math.min(90, 30 + Math.abs(x2 - x1) / 6) * (forward ? -1 : 1);
      return `M${x1} ${y} C${x1} ${y + lift}, ${x2} ${y + lift}, ${x2} ${y}`;
    }

    edge(a, b, kind) {
      const key = `${a}-${b}-${kind === 'ask' || kind === 'grant' || kind === 'deny' ? 'consent' : 'data'}`;
      let path = this.edges.get(key);
      if (!path) {
        path = el('path', { d: this.edgePath(a, b, kind), class: 'flow-edge', 'marker-end': 'url(#flow-arrow)' }, this.edgeLayer);
        if (this.nodes[a].kind === 'you' || this.nodes[b].kind === 'you') path.classList.add('flow-edge-consent');
        this.edges.set(key, path);
      }
      return path;
    }

    setState(i, state) {
      const n = this.nodes[i]; if (!n) return;
      n.state = state;
      n.stateEl.textContent = { idle: 'idle', working: 'working…', waiting: 'waiting for you', deciding: 'deciding', done: 'done', refused: 'refused' }[state] || state;
      n.g.classList.remove('is-working', 'is-waiting', 'is-deciding', 'is-refused');
      if (state !== 'idle' && state !== 'done') n.g.classList.add('is-' + state);
    }
    setData(i, text) { const n = this.nodes[i]; if (n) n.data.textContent = trunc(text, 30); }

    drain() {
      if (this.playing || !this.queue.length) return;
      this.playing = true;
      const { row } = this.queue.shift();
      this.play(row).then(() => { this.playing = false; setTimeout(() => this.drain(), STEP_GAP_MS); });
    }

    play(row) {
      const path = this.edge(row.from, row.to, row.kind);
      path.classList.add('is-active');
      if (row.tone) path.classList.add('flow-tone-' + row.tone);
      this.feedLine(row);
      return this.packet(path, row).then(() => {
        path.classList.remove('is-active');
        switch (row.kind) {
          case 'call':
            if (!/\(retry\)$/.test(row.label)) this.open.set(row.to, (this.open.get(row.to) || 0) + 1);
            this.setState(row.to, 'working'); this.setData(row.to, '← ' + row.text);
            if (this.nodes[row.from].kind !== 'you') this.setState(row.from, 'working');
            break;
          case 'ask':
            this.setState(row.from, row.pending ? 'waiting' : 'working'); this.setState(row.to, row.pending ? 'deciding' : 'idle');
            this.setData(row.to, row.label);
            break;
          case 'grant':
            this.setState(row.from, 'idle'); this.setState(row.to, 'working'); this.setData(row.to, 'approved: ' + row.text);
            break;
          case 'deny':
            this.setState(row.from, 'idle'); this.setState(row.to, 'refused'); this.setData(row.to, 'denied: ' + row.text);
            break;
          case 'reply': case 'error': {
            const left = Math.max(0, (this.open.get(row.from) || 1) - 1);
            this.open.set(row.from, left);
            this.setState(row.from, left ? 'working' : (row.kind === 'error' ? 'refused' : 'done'));
            this.setData(row.from, '→ ' + row.text);
            this.setData(row.to, '← ' + row.text);
            if (!this.stillWorking(row.to)) this.setState(row.to, this.nodes[row.to].kind === 'harness' ? 'done' : 'idle');
            break;
          }
        }
      });
    }

    stillWorking(i) { return (this.open.get(i) || 0) > 0 || [...this.open.entries()].some(([t, n]) => n > 0 && this.lastCaller(t) === i); }
    lastCaller(t) { for (let i = this.state.rows.length - 1; i >= 0; i--) { const r = this.state.rows[i]; if (r.kind === 'call' && r.to === t) return r.from; } return -1; }

    // packet moves a dot with a label along the edge, then resolves.
    packet(path, row) {
      return new Promise((resolve) => {
        const g = el('g', { class: 'flow-packet flow-packet-' + row.kind + (row.tone ? ' flow-tone-' + row.tone : '') }, this.packetLayer);
        el('circle', { r: 6 }, g);
        const label = el('text', { y: -12, 'text-anchor': 'middle', class: 'flow-packet-label' }, g);
        label.textContent = trunc(row.label + (row.text ? ': ' + row.text : ''), 48);
        const len = path.getTotalLength();
        const start = performance.now();
        const step = (now) => {
          const t = Math.min(1, (now - start) / PACKET_MS);
          const e = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t; // ease in-out
          const p = path.getPointAtLength(e * len);
          g.setAttribute('transform', `translate(${p.x} ${p.y})`);
          if (t < 1) requestAnimationFrame(step);
          else { g.classList.add('is-arrived'); setTimeout(() => { g.remove(); resolve(); }, 250); }
        };
        requestAnimationFrame(step);
      });
    }

    feedLine(row) {
      const ps = this.state.participants;
      const li = document.createElement('li');
      li.className = 'run-flow-line' + (row.tone ? ' run-tone-' + row.tone : '');
      li.innerHTML = `<span class="run-flow-time"></span><span class="run-flow-who"></span><span class="run-flow-what"><strong></strong><pre></pre></span>`;
      li.children[0].textContent = row.time;
      li.children[1].textContent = `${ps[row.from].name} → ${ps[row.to].name}`;
      li.children[2].firstChild.textContent = row.label + (row.pending ? ' · waiting for you' : '');
      li.children[2].lastChild.textContent = row.full || '';
      if (!row.full) li.children[2].lastChild.remove();
      this.feed.prepend(li);
    }

    replay() {
      if (!this.state) return;
      this.queue = []; this.playing = false; this.played = this.state.rows.length;
      this.layout(); this.feed.innerHTML = '';
      this.queue = this.state.rows.map((row, index) => ({ index, row }));
      this.noteEl.textContent = 'replaying';
      this.drain();
    }
  }

  const boot = () => document.querySelectorAll('[data-run-flow]:not([data-flow-ready])').forEach((root) => { root.dataset.flowReady = '1'; new Flow(root); });
  document.addEventListener('DOMContentLoaded', boot);
  document.body?.addEventListener('htmx:afterSwap', boot);
  document.body?.addEventListener('htmx:historyRestore', boot);
  if (document.readyState !== 'loading') boot();
})();
