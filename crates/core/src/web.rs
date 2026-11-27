//! WebAssembly entry for the AtlasSOC web page (ibert.se/AtlasSOC). The browser owns the network: it opens the
//! public GreyNoise WebSocket itself and hands each message here as UTF-8 text. This module only keeps the same
//! feed state and draws the same SOC view as the desktop apps, into an RGBA buffer the page copies to a canvas.
//! No network, no keys, no storage, no threads. Time and the UTC offset come from the browser on every call.
use crate::{clock, feed::State, render::soc::SocView, HEIGHT};

struct Web {
    state: State,
    view: SocView,
    input: Vec<u8>,
}

static mut WEB: Option<Web> = None;

/// Largest message the page may hand in at once; GreyNoise batches are far below this.
const MAX_MESSAGE: usize = 4 * 1024 * 1024;

#[allow(static_mut_refs)]
fn web() -> &'static mut Web {
    // Single-threaded WebAssembly: one instance, only ever touched from the page's main thread.
    unsafe {
        WEB.get_or_insert_with(|| Web {
            state: State::default(),
            view: {
                let mut view = SocView::new();
                view.options.web = true;
                view.options.radar_layer = false;
                view
            },
            input: Vec::new(),
        })
    }
}

/// Reserves `len` bytes for the next message and returns where the page writes them (0 when too large).
#[no_mangle]
pub extern "C" fn web_input(len: usize) -> *mut u8 {
    if len > MAX_MESSAGE {
        return std::ptr::null_mut();
    }
    let w = web();
    w.input.clear();
    w.input.resize(len, 0);
    w.input.as_mut_ptr()
}

/// Ingests the message the page wrote into the input buffer, received at `now_ms` (Unix milliseconds).
#[no_mangle]
pub extern "C" fn web_ingest(len: usize, now_ms: f64) {
    let w = web();
    let len = len.min(w.input.len());
    if let Ok(text) = std::str::from_utf8(&w.input[..len]) {
        let text = text.to_owned();
        w.state.ingest(&text, now_ms as u64);
    }
}

/// Marks the feed connected or not (drives the CONNECTING / OFFLINE / LIVE status line).
#[no_mangle]
pub extern "C" fn web_connected(connected: u32) {
    web().state.set_connected(connected != 0);
}

/// Draws one frame at `now_ms` with the browser's UTC offset in minutes east; returns the RGBA buffer
/// (`web_width()` x `web_height()` x 4 bytes), valid until the next call.
#[no_mangle]
pub extern "C" fn web_frame(now_ms: f64, offset_minutes_east: i32) -> *const u8 {
    clock::set_web_time(now_ms as u64, offset_minutes_east * 60);
    let w = web();
    let now = now_ms as u64;
    let snapshot = w.state.snapshot(now);
    let counts = w.state.counts(now);
    w.view.draw(&snapshot, counts, None, 0).as_ptr()
}

#[no_mangle]
pub extern "C" fn web_width() -> u32 {
    web().view.width()
}

#[no_mangle]
pub extern "C" fn web_height() -> u32 {
    HEIGHT
}
