use std::{
    error::Error,
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};
use std::{num::NonZeroU32, rc::Rc};
use tao::{
    dpi::{PhysicalPosition, PhysicalSize},
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    platform::windows::WindowBuilderExtWindows,
    window::{Fullscreen, WindowBuilder},
};
use threat_atlas_core::{
    render::panorama, saver::SaverSession, saver_config::SaverSettings, saver_ffi::SaverWorker,
    Session, HEIGHT, WIDTH,
};
use windows_sys::Win32::{
    Foundation::{HWND, POINT, RECT},
    UI::{
        Input::KeyboardAndMouse::GetAsyncKeyState,
        WindowsAndMessaging::{
            GetClientRect, GetCursorPos, IsWindow, MessageBoxW, IDNO, IDYES, MB_ICONERROR, MB_OK,
            MB_YESNOCANCEL,
        },
    },
};

pub fn show_error(message: &str) {
    let msg: Vec<u16> = format!("Threat Atlas: {message}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let title: Vec<u16> = "Threat Atlas".encode_utf16().chain(Some(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            msg.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(test)]
fn scaled_frame_layout(width: u32, height: u32) -> (u32, u32, u32, u32) {
    scaled_layout(width, height, WIDTH, HEIGHT)
}

/// Largest centred rectangle of the frame's shape that fits the window: (width, height, x offset, y offset).
fn scaled_layout(width: u32, height: u32, frame_w: u32, frame_h: u32) -> (u32, u32, u32, u32) {
    let scale = (width as f32 / frame_w as f32).min(height as f32 / frame_h as f32);
    let draw_width = ((frame_w as f32 * scale) as u32).min(width);
    let draw_height = ((frame_h as f32 * scale) as u32).min(height);
    let offset_x = (width - draw_width) / 2;
    let offset_y = (height - draw_height) / 2;
    (draw_width, draw_height, offset_x, offset_y)
}

/// The AtlasSOC view with the OSINT worker, used by the real screensaver and `--windowed`. The preview and the
/// panorama mode keep the classic view, and `ATLAS_SAVER_CLASSIC=1` forces it for before/after comparisons.
struct SocHost {
    session: SaverSession,
    worker: Option<SaverWorker>,
    frame_width: u32,
    window: (u32, u32),
    last_intel: Instant,
    last_reload: Instant,
}
impl SocHost {
    fn new() -> Self {
        // Reads AtlasSOC's settings.json only; without it every OSINT source stays off (no request is made).
        let worker = crate::saver_host::paths().map(|(settings, cache)| {
            let _ = fs::create_dir_all(&cache);
            SaverWorker::start(
                cache,
                settings,
                Box::new(crate::saver_host::CredentialKeys),
                None,
            )
        });
        let now = Instant::now();
        Self {
            session: SaverSession::new(),
            worker,
            frame_width: 0,
            window: (0, 0),
            last_intel: now.checked_sub(Duration::from_secs(2)).unwrap_or(now),
            last_reload: now,
        }
    }
    /// One RGBA frame for a window of this size, with its dimensions.
    fn frame(&mut self, width: u32, height: u32) -> (&[u8], u32, u32) {
        if self.window != (width, height) {
            self.window = (width, height);
            self.frame_width = self.session.fit_window(width, height);
        }
        if let Some(worker) = self.worker.as_mut() {
            if self.last_reload.elapsed() >= Duration::from_secs(10) {
                self.last_reload = Instant::now();
                worker.reload();
            }
            if self.last_intel.elapsed() >= Duration::from_secs(1) {
                self.last_intel = Instant::now();
                self.session.set_intel(worker.osint());
            }
        }
        let frame_width = self.frame_width;
        (self.session.frame(), frame_width, HEIGHT_SOC)
    }
}
/// The SOC frame is always this high.
const HEIGHT_SOC: u32 = 900;

fn panorama_setting() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|root| {
        PathBuf::from(root)
            .join("Threat Atlas")
            .join("screensaver-display-mode")
    })
}

/// What Windows (or a person) asked the screensaver to do.
#[derive(Debug, PartialEq, Eq)]
enum Mode {
    /// The settings dialog, with the Screen Saver Settings window as its owner when Windows names one.
    Configure(Option<usize>),
    /// The small preview inside Screen Saver Settings, drawn into this parent window.
    Preview(usize),
    /// Fullscreen screensaver.
    Run,
    /// A normal window, for testing.
    Windowed,
}

/// One argument without quotes or surrounding space, lowercase.
fn normalized(arg: &str) -> String {
    arg.trim().trim_matches('"').trim().to_ascii_lowercase()
}

/// `/c`, `-c`, `/c:1234` or `/c 1234`: the configuration request and the window handle, if any.
fn configure_flag(arg: &str) -> Option<Option<usize>> {
    let rest = arg.strip_prefix("/c").or_else(|| arg.strip_prefix("-c"))?;
    match rest.strip_prefix(':') {
        Some(handle) => Some(handle.trim().parse().ok()),
        None if rest.is_empty() => Some(None),
        None => None,
    }
}

/// Reads the command line the way Windows passes it: `/s` runs the saver, `/p HWND` or `/p:HWND` draws the preview,
/// `/c`, `/c:HWND` or no argument at all (Explorer's Configure) opens the settings dialog. A `/c` anywhere wins: some
/// shell launches add it after the `/S` of the .scr file type's own command line, and a request for settings must
/// never start the fullscreen saver.
fn parse_mode(args: &[String]) -> Result<Mode, String> {
    let args: Vec<String> = args
        .iter()
        .map(|a| normalized(a))
        .filter(|a| !a.is_empty())
        .collect();
    let Some(first) = args.first() else {
        return Ok(Mode::Configure(None));
    };
    if let Some((index, handle)) = args
        .iter()
        .enumerate()
        .find_map(|(i, a)| configure_flag(a).map(|h| (i, h)))
    {
        let handle = handle.or_else(|| args.get(index + 1).and_then(|next| next.parse().ok()));
        return Ok(Mode::Configure(handle));
    }
    if let Some(rest) = first
        .strip_prefix("/p")
        .or_else(|| first.strip_prefix("-p"))
    {
        let raw = match rest.strip_prefix(':') {
            Some(handle) => Some(handle.to_string()),
            None if rest.is_empty() => args.get(1).cloned(),
            None => return Err("Use /s, /p HWND, /c, or --windowed".into()),
        };
        let raw = raw.ok_or("Preview requires a parent HWND")?;
        return raw
            .trim()
            .parse::<usize>()
            .map(Mode::Preview)
            .map_err(|_| "Preview requires a parent HWND".into());
    }
    match first.as_str() {
        "/s" | "-s" => Ok(Mode::Run),
        "--windowed" => Ok(Mode::Windowed),
        _ if first.starts_with("/s:") || first.starts_with("-s:") => Ok(Mode::Run),
        _ => Err("Use /s, /p HWND, /c, or --windowed".into()),
    }
}

/// The settings dialog: display mode (standard or panorama). OSINT sources and keys are chosen in AtlasSOC.
fn configure(owner: Option<usize>) -> Result<(), Box<dyn Error>> {
    let path = panorama_setting().ok_or("Cannot find the local settings folder")?;
    let enabled = fs::read_to_string(&path).is_ok_and(|mode| mode.trim() == "panorama");
    let mode = if enabled { "Panorama" } else { "Standard" };
    let message: Vec<u16> = format!(
        "Current display mode: {mode}\n\nYes: Panorama across two matching side-by-side displays\nNo: Standard display mode\nCancel: Keep the current mode\n\nLive GreyNoise public threat-map telemetry. No cookies, browser, account or API key required.\nThe AtlasSOC view with rotating OSINT cards is used here. OSINT sources, watched domains and API keys are chosen in AtlasSOC Settings; this screen saver only reads them. With nothing chosen, no OSINT request is made.\nGreen LIVE means records arrived within 10 seconds. Routes expire after 6 seconds. Offline feeds reconnect automatically.\nThe header shows UTC and system local time. Observation times are receipt times in UTC.\nUse Windows Screen Saver Settings for idle time and lock behavior."
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    let title: Vec<u16> = "Threat Atlas Screen Saver"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // Owned by the Screen Saver Settings window when Windows passed one, so the dialog stays in front of it.
    let owner = owner
        .map(|h| h as HWND)
        .filter(|&h| unsafe { IsWindow(h) } != 0)
        .unwrap_or(std::ptr::null_mut());
    let choice = unsafe { MessageBoxW(owner, message.as_ptr(), title.as_ptr(), MB_YESNOCANCEL) };
    if let Some(mode) = match choice {
        IDYES => Some("panorama"),
        IDNO => Some("standard"),
        _ => None,
    } {
        fs::create_dir_all(path.parent().ok_or("Invalid settings path")?)?;
        fs::write(path, mode)?;
    }
    Ok(())
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = parse_mode(&args)?;
    let parent: Option<HWND> = match mode {
        Mode::Configure(owner) => return configure(owner),
        Mode::Preview(raw) => {
            let hwnd = raw as HWND;
            if unsafe { IsWindow(hwnd) } == 0 {
                return Err("Invalid preview window".into());
            }
            Some(hwnd)
        }
        Mode::Run | Mode::Windowed => None,
    };
    let preview = parent.is_some();
    let windowed = mode == Mode::Windowed;
    let event_loop = EventLoop::new();
    let mut panorama_size = None;
    let mut panorama_origin = None;
    let mut builder = WindowBuilder::new()
        .with_title("Threat Atlas")
        .with_decorations(windowed)
        .with_skip_taskbar(!windowed)
        .with_inner_size(PhysicalSize::new(1280, 800));
    if let Some(hwnd) = parent {
        let mut rect: RECT = unsafe { std::mem::zeroed() };
        if unsafe { GetClientRect(hwnd, &mut rect) } == 0 {
            return Err("Cannot read preview bounds".into());
        }
        builder = builder
            .with_parent_window(hwnd as _)
            .with_position(PhysicalPosition::new(0, 0))
            .with_inner_size(PhysicalSize::new(
                rect.right.max(1) as u32,
                rect.bottom.max(1) as u32,
            ))
            .with_focused(false);
    } else if !windowed {
        let panorama = panorama_setting()
            .and_then(|path| fs::read_to_string(path).ok())
            .is_some_and(|mode| mode.trim() == "panorama");
        let mut monitors: Vec<_> = event_loop.available_monitors().take(3).collect();
        monitors.sort_by_key(|monitor| monitor.position().x);
        builder = match monitors.as_slice() {
            [left, right]
                if panorama
                    && left.size() == right.size()
                    && left.scale_factor() == right.scale_factor()
                    && left.position().y == right.position().y
                    && i64::from(left.position().x) + i64::from(left.size().width)
                        == i64::from(right.position().x)
                    && panorama::fits(left.size().width * 2, left.size().height) =>
            {
                let size = PhysicalSize::new(left.size().width * 2, left.size().height);
                panorama_size = Some(size);
                panorama_origin = Some(left.position());
                // A resizable window keeps an invisible frame that offsets the picture.
                builder
                    .with_resizable(false)
                    .with_position(left.position())
                    .with_inner_size(size)
                    .with_always_on_top(true)
            }
            _ => builder.with_fullscreen(Some(Fullscreen::Borderless(None))),
        };
    }
    let window = Rc::new(builder.build(&event_loop)?);
    if let Some(origin) = panorama_origin {
        if let (Ok(inner), Ok(outer)) = (window.inner_position(), window.outer_position()) {
            window.set_outer_position(PhysicalPosition::new(
                outer.x + origin.x - inner.x,
                outer.y + origin.y - inner.y,
            ));
        }
    }
    if !windowed && !preview {
        window.set_cursor_visible(false);
    }
    let context = softbuffer::Context::new(window.clone())?;
    let mut surface = softbuffer::Surface::new(&context, window.clone())?;
    let soc_view = panorama_size.is_none()
        && !preview
        && std::env::var_os("ATLAS_SAVER_CLASSIC").is_none_or(|v| v != "1");
    let mut soc = soc_view.then(SocHost::new);
    let mut session = (!soc_view).then(|| match panorama_size {
        Some(size) => Session::panorama(size.width, size.height),
        None => Session::new(),
    });
    let (frame_width, frame_height) = session
        .as_ref()
        .map_or((WIDTH, HEIGHT), |s| s.renderer.size());
    // Read once per launch from AtlasSOC's settings file, so every start path (idle timer, /s, shortcut) honours
    // it without extra arguments. Missing or corrupt file: any input ends the saver, as before.
    let dismiss = crate::saver_host::paths()
        .map(|(settings, _)| SaverSettings::load(&settings).dismiss)
        .unwrap_or_default();
    let started = Instant::now();
    let mut origin: POINT = unsafe { std::mem::zeroed() };
    unsafe {
        GetCursorPos(&mut origin);
    }
    let mut previous_keys = [false; 256];
    for (key, previous) in previous_keys.iter_mut().enumerate().skip(1) {
        *previous = unsafe { GetAsyncKeyState(key as i32) } < 0;
    }
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(50));
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *flow = ControlFlow::Exit;
        }
        if let Event::MainEventsCleared = event {
            if let Some(hwnd) = parent {
                if unsafe { IsWindow(hwnd) } == 0 {
                    *flow = ControlFlow::Exit;
                    return;
                }
                let mut rect: RECT = unsafe { std::mem::zeroed() };
                if unsafe { GetClientRect(hwnd, &mut rect) } != 0 {
                    let size =
                        PhysicalSize::new(rect.right.max(1) as u32, rect.bottom.max(1) as u32);
                    if window.inner_size() != size {
                        window.set_inner_size(size);
                    }
                }
            } else if !windowed && started.elapsed() > Duration::from_secs(2) {
                let mut point: POINT = unsafe { std::mem::zeroed() };
                unsafe {
                    GetCursorPos(&mut point);
                }
                let (mut clicked, mut key_pressed) = (false, false);
                for (key, previous) in previous_keys.iter_mut().enumerate().skip(1) {
                    let down = unsafe { GetAsyncKeyState(key as i32) } < 0;
                    if down && !*previous {
                        if is_mouse_button(key) {
                            clicked = true;
                        } else {
                            key_pressed = true;
                        }
                    }
                    *previous = down;
                }
                let moved = (point.x - origin.x).abs() > 5 || (point.y - origin.y).abs() > 5;
                if dismiss.ends_saver(moved, clicked, key_pressed) {
                    *flow = ControlFlow::Exit;
                    return;
                }
            } else {
                unsafe {
                    GetCursorPos(&mut origin);
                }
                for (key, previous) in previous_keys.iter_mut().enumerate().skip(1) {
                    *previous = unsafe { GetAsyncKeyState(key as i32) } < 0;
                }
            }
            let size = window.inner_size();
            if let (Some(width), Some(height)) =
                (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
            {
                if surface.resize(width, height).is_err() {
                    *flow = ControlFlow::Exit;
                    return;
                }
                let (rgba, frame_width, frame_height) = match (soc.as_mut(), session.as_mut()) {
                    (Some(host), _) => host.frame(size.width, size.height),
                    (None, Some(classic)) => (classic.frame(), frame_width, frame_height),
                    (None, None) => return,
                };
                if let Ok(mut buffer) = surface.buffer_mut() {
                    // The panorama frame already has the window's shape and fills it.
                    let (dw, dh, ox, oy) = if panorama_size.is_some() {
                        (size.width, size.height, 0, 0)
                    } else {
                        scaled_layout(size.width, size.height, frame_width, frame_height)
                    };
                    let scale_x = dw as f32 / frame_width as f32;
                    let scale_y = if panorama_size.is_some() {
                        dh as f32 / frame_height as f32
                    } else {
                        scale_x
                    };
                    buffer.fill(0x00060c14);
                    for y in 0..dh {
                        let sy = ((y as f32 / scale_y) as u32).min(frame_height - 1);
                        for x in 0..dw {
                            let sx = ((x as f32 / scale_x) as u32).min(frame_width - 1);
                            let i = ((sy * frame_width + sx) * 4) as usize;
                            buffer[((y + oy) * size.width + x + ox) as usize] = ((rgba[i] as u32)
                                << 16)
                                | ((rgba[i + 1] as u32) << 8)
                                | rgba[i + 2] as u32;
                        }
                    }
                    if buffer.present().is_err() {
                        *flow = ControlFlow::Exit;
                    }
                }
            }
        }
    });
}

/// Virtual-key codes that are mouse buttons, not keyboard keys: VK_LBUTTON, VK_RBUTTON, VK_MBUTTON, VK_XBUTTON1 and
/// VK_XBUTTON2. 0x03 is VK_CANCEL (Ctrl+Break), a keyboard key.
fn is_mouse_button(vk: usize) -> bool {
    matches!(vk, 0x01 | 0x02 | 0x04 | 0x05 | 0x06)
}

#[cfg(test)]
mod tests {
    use super::{is_mouse_button, scaled_frame_layout};
    use threat_atlas_core::{HEIGHT, WIDTH};

    fn mode(args: &[&str]) -> Result<super::Mode, String> {
        super::parse_mode(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn configure_is_chosen_for_every_settings_request() {
        use super::Mode::*;
        assert_eq!(mode(&[]), Ok(Configure(None)));
        assert_eq!(mode(&["/c"]), Ok(Configure(None)));
        assert_eq!(mode(&["/C"]), Ok(Configure(None)));
        assert_eq!(mode(&["-c"]), Ok(Configure(None)));
        assert_eq!(mode(&["/c:394812"]), Ok(Configure(Some(394812))));
        assert_eq!(mode(&["/C:394812"]), Ok(Configure(Some(394812))));
        assert_eq!(mode(&["/c", "394812"]), Ok(Configure(Some(394812))));
        assert_eq!(mode(&["\"/c\""]), Ok(Configure(None)));
        assert_eq!(mode(&[" /c "]), Ok(Configure(None)));
        // The .scr file type runs `"%1" /S`; a shell launch that appends `/c` must still open the settings.
        assert_eq!(mode(&["/S", "/c"]), Ok(Configure(None)));
        assert_eq!(mode(&["/s", "/c:77"]), Ok(Configure(Some(77))));
        assert_eq!(mode(&["/c:not-a-window"]), Ok(Configure(None)));
    }

    #[test]
    fn run_preview_and_windowed_are_unchanged() {
        use super::Mode::*;
        assert_eq!(mode(&["/s"]), Ok(Run));
        assert_eq!(mode(&["/S"]), Ok(Run));
        assert_eq!(mode(&["-s"]), Ok(Run));
        assert_eq!(mode(&["--windowed"]), Ok(Windowed));
        assert_eq!(mode(&["/p", "1234"]), Ok(Preview(1234)));
        assert_eq!(mode(&["/p:1234"]), Ok(Preview(1234)));
        assert_eq!(mode(&["/P", "1234"]), Ok(Preview(1234)));
        assert!(mode(&["/p"]).is_err());
        assert!(mode(&["/p", "x"]).is_err());
        assert!(mode(&["/x"]).is_err());
        assert!(mode(&["/config"]).is_err());
    }

    #[test]
    fn centers_and_fits_common_display_resolutions() {
        for (width, height) in [
            (1024, 768),
            (1280, 720),
            (1280, 800),
            (1920, 1080),
            (2560, 1440),
            (3440, 1440),
            (3840, 2160),
            (1080, 1920),
        ] {
            let (draw_width, draw_height, offset_x, offset_y) = scaled_frame_layout(width, height);
            assert!(draw_width <= width && draw_height <= height);
            assert!(width - draw_width - offset_x <= offset_x + 1);
            assert!(height - draw_height - offset_y <= offset_y + 1);
            let source_aspect = WIDTH as f64 / HEIGHT as f64;
            let drawn_aspect = draw_width as f64 / draw_height as f64;
            assert!((source_aspect - drawn_aspect).abs() < 0.003);
        }
    }

    #[test]
    fn soc_frames_of_any_width_fit_without_overflow() {
        for (w, h) in [
            (1920, 1080),
            (2560, 1440),
            (3440, 1440),
            (1280, 800),
            (1080, 1920),
        ] {
            let fw = threat_atlas_core::saver::frame_width_for_window(w, h);
            let (dw, dh, ox, oy) = super::scaled_layout(w, h, fw, 900);
            assert!(dw <= w && dh <= h && ox + dw <= w && oy + dh <= h);
        }
    }

    #[test]
    fn uses_expected_letterboxing_for_representative_displays() {
        assert_eq!(scaled_frame_layout(1280, 720), (1152, 720, 64, 0));
        assert_eq!(scaled_frame_layout(1280, 800), (1280, 800, 0, 0));
        assert_eq!(scaled_frame_layout(1024, 768), (1024, 640, 0, 64));
        assert_eq!(scaled_frame_layout(3440, 1440), (2304, 1440, 568, 0));
        assert_eq!(scaled_frame_layout(3840, 2160), (3456, 2160, 192, 0));
    }

    #[test]
    fn mouse_buttons_are_split_from_keyboard_keys() {
        for vk in [0x01, 0x02, 0x04, 0x05, 0x06] {
            assert!(is_mouse_button(vk), "{vk:#x}");
        }
        // VK_CANCEL, Backspace, Enter, Esc, Space, A and F1 stay keys.
        for vk in [0x03, 0x08, 0x0D, 0x1B, 0x20, 0x41, 0x70] {
            assert!(!is_mouse_button(vk), "{vk:#x}");
        }
    }
}
