// AtlasSOC web: the browser owns the GreyNoise socket; the shared core (atlassoc.wasm) keeps the feed state and
// draws each frame. Nothing starts before the user presses "Start live view". No storage, cookies or tracking.
'use strict';
(() => {
  const FEED = 'wss://threat-map-api.greynoise.io/ws';
  const MAX_MESSAGE = 4 * 1024 * 1024;
  const $ = id => document.getElementById(id);
  const canvas = $('soc'), ctx = canvas.getContext('2d'), stage = $('stage');
  const encoder = new TextEncoder();
  // The core draws a 900-pixel-high frame (1440 to 2160 wide, following the screen's shape) into `frame`;
  // the visible canvas is sized to the stage in device pixels and the frame is scaled into it, so the map
  // stays sharp at any size and pixel density (devicePixelRatio).
  const frame = document.createElement('canvas'), frameCtx = frame.getContext('2d');
  let wasm = null, socket = null, running = false, retry = 1000, frameId = 0, reconnectTimer = 0;
  let layoutDirty = true, dprQuery = null;

  async function load() {
    if (wasm) return wasm;
    const bytes = await (await fetch('atlassoc.wasm', { credentials: 'omit' })).arrayBuffer();
    const { instance } = await WebAssembly.instantiate(bytes, {});
    wasm = instance.exports;
    return wasm;
  }

  function status(text) { $('status').textContent = text; }

  function connect() {
    if (!running || document.hidden || socket) return;
    status('Connecting…');
    socket = new WebSocket(FEED);
    socket.onopen = () => { retry = 1000; wasm.web_connected(1); status('Live · GreyNoise public threat map'); };
    socket.onmessage = event => {
      if (typeof event.data !== 'string') return;
      const bytes = encoder.encode(event.data);
      if (bytes.length > MAX_MESSAGE) return;
      const ptr = wasm.web_input(bytes.length);
      if (!ptr) return;
      new Uint8Array(wasm.memory.buffer, ptr, bytes.length).set(bytes);
      wasm.web_ingest(bytes.length, Date.now());
    };
    socket.onclose = () => {
      socket = null;
      if (wasm) wasm.web_connected(0);
      if (running && !document.hidden) {
        status('Reconnecting…');
        reconnectTimer = setTimeout(connect, retry);
        retry = Math.min(retry * 2, 30000);
      }
    };
    socket.onerror = () => { /* onclose follows and schedules the retry */ };
  }

  function disconnect() {
    clearTimeout(reconnectTimer);
    if (socket) { const s = socket; socket = null; s.onclose = null; s.close(); }
    if (wasm) wasm.web_connected(0);
  }

  // Fits the canvas to the stage: picks the frame layout for the stage's shape, then sizes the canvas in CSS
  // pixels (keeping the frame's shape, centred) and its backing store in device pixels.
  function layout() {
    layoutDirty = false;
    const box = stage.getBoundingClientRect();
    if (box.width < 1 || box.height < 1) return;
    if (wasm && wasm.web_layout) wasm.web_layout(Math.round(box.width), Math.round(box.height));
    const fw = wasm ? wasm.web_width() : 1440, fh = wasm ? wasm.web_height() : 900;
    const cssW = Math.max(1, Math.floor(Math.min(box.width, box.height * fw / fh)));
    const cssH = Math.max(1, Math.floor(cssW * fh / fw));
    canvas.style.width = cssW + 'px';
    canvas.style.height = cssH + 'px';
    const dpr = Math.min(Math.max(window.devicePixelRatio || 1, 1), 4);
    const w = Math.round(cssW * dpr), h = Math.round(cssH * dpr);
    if (canvas.width !== w) canvas.width = w;
    if (canvas.height !== h) canvas.height = h;
    watchDpr();
  }

  // Re-layout when the pixel density changes (browser zoom, or the window moves to another display).
  function watchDpr() {
    const dpr = window.devicePixelRatio || 1;
    if (dprQuery && dprQuery.dpr === dpr) return;
    if (dprQuery) dprQuery.mql.removeEventListener('change', relayout);
    const mql = window.matchMedia(`(resolution: ${dpr}dppx)`);
    if (mql.addEventListener) mql.addEventListener('change', relayout);
    dprQuery = { mql, dpr };
  }

  // The visible height. iOS Safari keeps 100vh at the toolbar-less height and older versions lack dvh, so the
  // live layer takes its height from innerHeight (not visualViewport, which shrinks with pinch zoom).
  function relayout() {
    layoutDirty = true;
    const h = Math.round(window.innerHeight);
    if (h > 0) document.documentElement.style.setProperty('--app-h', h + 'px');
    if (running && (window.scrollX || window.scrollY)) window.scrollTo(0, 0);
  }

  // Fullscreen API where the browser has it for page elements (desktop, Android, iPad). iPhone Safari only allows
  // it for video, so there the button stays hidden and the fixed full-viewport layer does the job; added to the
  // Home Screen, the page opens without browser bars (apple-mobile-web-app-capable).
  const root = document.documentElement;
  const fsElement = () => document.fullscreenElement || document.webkitFullscreenElement || null;
  const fsEnabled = !!(document.fullscreenEnabled || document.webkitFullscreenEnabled) &&
    !!(root.requestFullscreen || root.webkitRequestFullscreen);
  function enterFullscreen() {
    if (!fsEnabled || fsElement()) return;
    try {
      const p = root.requestFullscreen ? root.requestFullscreen({ navigationUI: 'hide' }) : root.webkitRequestFullscreen();
      if (p && p.catch) p.catch(() => {});
    } catch (e) { /* not allowed here; the fixed layer still fills the viewport */ }
  }
  function exitFullscreen() {
    if (!fsElement()) return;
    try {
      const p = document.exitFullscreen ? document.exitFullscreen() : document.webkitExitFullscreen();
      if (p && p.catch) p.catch(() => {});
    } catch (e) { /* ignore */ }
  }
  function fullscreenChanged() {
    $('fullscreen').textContent = fsElement() ? 'Exit full screen' : 'Full screen';
    relayout();
  }

  function draw() {
    if (!running) return;
    if (layoutDirty) layout();
    const offsetEast = -new Date().getTimezoneOffset();
    const ptr = wasm.web_frame(Date.now(), offsetEast);
    const w = wasm.web_width(), h = wasm.web_height();
    if (ptr && w && h) {
      if (frame.width !== w) frame.width = w;
      if (frame.height !== h) frame.height = h;
      const pixels = new Uint8ClampedArray(wasm.memory.buffer, ptr, w * h * 4);
      frameCtx.putImageData(new ImageData(pixels, w, h), 0, 0);
      ctx.imageSmoothingEnabled = true;
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(frame, 0, 0, canvas.width, canvas.height);
    }
    frameId = requestAnimationFrame(draw);
  }

  async function start() {
    $('start').disabled = true;
    // Touch devices go full screen straight away (this click is the user gesture the API needs).
    if (window.matchMedia('(pointer: coarse)').matches) enterFullscreen();
    try {
      await load();
    } catch (e) {
      $('start').disabled = false;
      $('start').textContent = 'Could not load (WebAssembly needed). Try again';
      return;
    }
    running = true;
    document.body.classList.add('is-live');
    $('gate').hidden = true;
    $('live').hidden = false;
    $('fullscreen').hidden = !fsEnabled;
    relayout();
    connect();
    frameId = requestAnimationFrame(draw);
  }

  function stop() {
    running = false;
    cancelAnimationFrame(frameId);
    disconnect();
    exitFullscreen();
    document.body.classList.remove('is-live');
    $('live').hidden = true;
    $('gate').hidden = false;
    $('start').disabled = false;
  }

  document.addEventListener('visibilitychange', () => {
    if (!running) return;
    if (document.hidden) { disconnect(); status('Paused (tab hidden)'); }
    else { retry = 1000; connect(); }
  });

  if (window.ResizeObserver) new ResizeObserver(relayout).observe(stage);
  window.addEventListener('resize', relayout);
  window.addEventListener('orientationchange', () => { relayout(); setTimeout(relayout, 300); });
  if (window.visualViewport) window.visualViewport.addEventListener('resize', relayout);
  document.addEventListener('fullscreenchange', fullscreenChanged);
  document.addEventListener('webkitfullscreenchange', fullscreenChanged);
  relayout();

  $('start').addEventListener('click', start);
  $('stop').addEventListener('click', stop);
  $('fullscreen').addEventListener('click', () => { if (fsElement()) exitFullscreen(); else enterFullscreen(); });
})();
