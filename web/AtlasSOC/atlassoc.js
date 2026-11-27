// AtlasSOC web: the browser owns the GreyNoise socket; the shared core (atlassoc.wasm) keeps the feed state and
// draws each frame. Nothing starts before the user presses "Start live view". No storage, cookies or tracking.
'use strict';
(() => {
  const FEED = 'wss://threat-map-api.greynoise.io/ws';
  const MAX_MESSAGE = 4 * 1024 * 1024;
  const $ = id => document.getElementById(id);
  const canvas = $('soc'), ctx = canvas.getContext('2d');
  const encoder = new TextEncoder();
  let wasm = null, socket = null, running = false, retry = 1000, frameId = 0, reconnectTimer = 0;

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

  function draw() {
    if (!running) return;
    const offsetEast = -new Date().getTimezoneOffset();
    const ptr = wasm.web_frame(Date.now(), offsetEast);
    const w = wasm.web_width(), h = wasm.web_height();
    if (ptr && w && h) {
      if (canvas.width !== w) canvas.width = w;
      if (canvas.height !== h) canvas.height = h;
      const pixels = new Uint8ClampedArray(wasm.memory.buffer, ptr, w * h * 4);
      ctx.putImageData(new ImageData(pixels, w, h), 0, 0);
    }
    frameId = requestAnimationFrame(draw);
  }

  async function start() {
    $('start').disabled = true;
    try {
      await load();
    } catch (e) {
      $('start').disabled = false;
      $('start').textContent = 'Could not load (WebAssembly needed). Try again';
      return;
    }
    running = true;
    $('gate').hidden = true;
    $('live').hidden = false;
    connect();
    frameId = requestAnimationFrame(draw);
  }

  function stop() {
    running = false;
    cancelAnimationFrame(frameId);
    disconnect();
    $('live').hidden = true;
    $('gate').hidden = false;
    $('start').disabled = false;
  }

  document.addEventListener('visibilitychange', () => {
    if (!running) return;
    if (document.hidden) { disconnect(); status('Paused (tab hidden)'); }
    else { retry = 1000; connect(); }
  });

  $('start').addEventListener('click', start);
  $('stop').addEventListener('click', stop);
})();
