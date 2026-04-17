use std::io::{Read, Write, Result};
use std::sync::{LazyLock, RwLock};
use bytes::{Buf, BytesMut};
use tungstenite::protocol::Role;
// server = outgoing, client = incoming. fed into tungstenite's ws parser
static SERVER_BUF: LazyLock<RwLock<BytesMut>> =
    LazyLock::new(|| RwLock::new(BytesMut::with_capacity(8192)));
static CLIENT_BUF: LazyLock<RwLock<BytesMut>> =
    LazyLock::new(|| RwLock::new(BytesMut::with_capacity(8192)));

pub fn push_read(role: Role, data: &[u8]) {
    let buf = match role {
        Role::Server => &SERVER_BUF,
        Role::Client => &CLIENT_BUF,
    };
    buf.write().unwrap().extend_from_slice(data);
}

pub struct HookedStream { role: Role }

impl HookedStream {
    pub fn new(role: Role) -> Self { Self { role } }
}

impl Read for HookedStream {
    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        let store = match self.role {
            Role::Server => &SERVER_BUF,
            Role::Client => &CLIENT_BUF,
        };
        let mut buf = store.write().unwrap();
        if buf.is_empty() {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let n = buf.len().min(out.len());
        out[..n].copy_from_slice(&buf[..n]);
        buf.advance(n);
        Ok(n)
    }
}

// dummy sink for tungstenite, we never read this back
static OUTGOING_BUF: LazyLock<RwLock<BytesMut>> =
    LazyLock::new(|| RwLock::new(BytesMut::with_capacity(8192)));

impl Write for HookedStream {
    fn write(&mut self, data: &[u8]) -> Result<usize> {
        OUTGOING_BUF.write().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> Result<()> { Ok(()) }
}

use std::sync::atomic::AtomicU64;
static INITIAL_CONN: AtomicU64 = AtomicU64::new(0);
// set once masquerade fires. the next session log in nex.rs picks it up
#[cfg(feature = "avaru-guard")]
pub static MASQUERADE_APPLIED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// original owner pid before rewrite, used to grow the blocklist
#[cfg(feature = "avaru-guard")]
pub static LAST_MASQ_ORIGINAL_OWNER: AtomicU64 = AtomicU64::new(0);

// only pc=0 actually mattered. max_p/state are harmless but don't do anything
#[cfg(feature = "avaru-guard")]
const MASQ_PARTICIPATION_COUNT: u32 = 0;
#[cfg(feature = "avaru-guard")]
const MASQ_MAX_PARTICIPANTS: Option<u16> = None;
#[cfg(feature = "avaru-guard")]
const MASQ_STATE: Option<u32> = None;

extern "C" {
    #[link_name = "_ZN2nn3ssl10Connection6CreateEPNS0_7ContextE"]
    fn ssl_create(this: u64, context: u64) -> i32;

    #[link_name = "_ZN2nn3ssl10Connection4ReadEPcPij"]
    fn ssl_read(this: u64, buf: *mut u8, out_size: *mut i32, len: usize) -> i32;

    #[link_name = "\u{1}_ZN2nn3ssl10Connection5WriteEPKcPij"]
    fn ssl_write(this: u64, buf: *const u8, out_size: *mut i32, len: usize) -> i32;
}

// rebuild a valid ws binary frame from a saved method 40 rmc.
// kept around for the phase 4 counter-attack
#[allow(dead_code)]
#[cfg(feature = "avaru-guard")]
fn build_websocket_client_frame(rmc_payload: &[u8]) -> Vec<u8> {
    // bump call_id so the server doesn't flag it as a dup
    let new_call_id = crate::net::nex::LAST_CALL_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst).wrapping_add(1000);
    let mut rmc = rmc_payload.to_vec();
    if rmc.len() >= 9 {
        let cid_bytes = new_call_id.to_le_bytes();
        rmc[5] = cid_bytes[0];
        rmc[6] = cid_bytes[1];
        rmc[7] = cid_bytes[2];
        rmc[8] = cid_bytes[3];
    }

    // reuse the prudp header, just bump seq_id
    let prudp = {
        let hdr_guard = crate::net::nex::LAST_SEARCH_PRUDP_HEADER.read().unwrap();
        let hdr = hdr_guard.as_ref().expect("PRUDP header must be captured before replay");
        let seq = crate::net::nex::LAST_SEARCH_SEQ_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst).wrapping_add(1);
        let new_payload_size = (rmc.len() as u16).to_le_bytes();
        let mut p = Vec::with_capacity(hdr.len() + rmc.len());
        p.extend_from_slice(hdr);
        p[2] = new_payload_size[0];
        p[3] = new_payload_size[1];
        let s = seq.to_le_bytes();
        p[10] = s[0];
        p[11] = s[1];
        p.extend_from_slice(&rmc);
        p
    };

    // ws binary frame: 0x82 (FIN+bin) with MASK bit set
    let payload_len = prudp.len();
    let mut frame = Vec::with_capacity(payload_len + 14);
    frame.push(0x82);
    if payload_len < 126 {
        frame.push(0x80 | payload_len as u8);
    } else if payload_len < 65536 {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
    }
    let tick = unsafe { skyline::nn::os::GetSystemTick() };
    let mask: [u8; 4] = [
        (tick & 0xff) as u8,
        ((tick >> 8) & 0xff) as u8,
        ((tick >> 16) & 0xff) as u8,
        ((tick >> 24) & 0xff) as u8,
    ];
    frame.extend_from_slice(&mask);
    for (i, b) in prudp.iter().enumerate() {
        frame.push(b ^ mask[i & 3]);
    }
    frame
}

#[allow(dead_code)]
#[cfg(feature = "avaru-guard")]
pub unsafe fn inject_search_replay() -> bool {
    let conn = INITIAL_CONN.load(std::sync::atomic::Ordering::SeqCst);
    if conn == 0 {
        return false;
    }
    let rmc = {
        let g = crate::net::nex::LAST_SEARCH_PRUDP_PAYLOAD.read().unwrap();
        match g.as_ref() {
            Some(v) => v.clone(),
            None => {
                return false;
            }
        }
    };
    let frame = build_websocket_client_frame(&rmc);
    let mut out_size: i32 = 0;
    let rc = ssl_write(conn, frame.as_ptr(), &mut out_size as *mut i32, frame.len());
    rc >= 0 && out_size > 0
}

// outer Some = method 40 response, None = not our packet.
// inner Some(reason) = suspect, None = normal session
#[cfg(feature = "avaru-guard")]
unsafe fn quick_detect_suspect(data: &[u8]) -> Option<Option<&'static str>> {
    if data.len() < 20 || data[0] != 0x82 { return None; }
    let ws_hdr = if data[1] < 126 { 2 } else if data[1] == 126 { 4 } else { return None };
    let p = ws_hdr;
    if p + 12 > data.len() || data[p] != 0x80 { return None; }
    let psd_len = data[p + 1] as usize;
    let rmc = p + 12 + psd_len;
    if rmc + 14 > data.len() { return None; }
    let proto = data[rmc + 4];
    if proto & 0x80 != 0 { return None; }
    if proto != 0x6D { return None; }
    if data[rmc + 5] == 0 { return None; }
    let method_id = u32::from_le_bytes([data[rmc + 10], data[rmc + 11], data[rmc + 12], data[rmc + 13]]) & 0x7FFF;
    if method_id != 40 { return None; }
    // MatchmakeSession sits right after the 14-byte RmcSuccess header
    let ms = rmc + 14;
    // Gathering: header(5) + id(4) + owner(8) + host(8) + min_p(2) + max_p(2)
    let max_p_off = ms + 5 + 4 + 8 + 8 + 2;
    if max_p_off + 2 > data.len() { return Some(None); }
    let max_participants = u16::from_le_bytes([data[max_p_off], data[max_p_off + 1]]);
    if max_participants > 2 { return Some(Some("max_p>2")); }
    // + policy(4) + arg(4) + flags(4) + state(4), then description
    let mut o = max_p_off + 2 + 4 + 4 + 4 + 4;
    if o + 2 > data.len() { return Some(None); }
    let desc_len = u16::from_le_bytes([data[o], data[o + 1]]) as usize;
    o += 2 + desc_len;
    // MatchmakeSession header(5) + game_mode(4)
    o += 5 + 4;
    if o + 4 > data.len() { return Some(None); }
    let attr_count = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
    o += 4 + attr_count * 4;
    o += 1 + 4; // open_participation + matchmake_system_type
    if o + 4 > data.len() { return Some(None); }
    let app_buf_len = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
    o += 4;
    if app_buf_len == 0 || o >= data.len() { return Some(None); }
    if data[o] == 0x02 { Some(Some("app_buf[0]=0x02")) } else { Some(None) }
}

// pull the owner name (UTF-16LE) from app_buf+0x1e.
// masquerade doesn't touch this region so calling order doesn't matter
#[cfg(feature = "avaru-guard")]
unsafe fn extract_suspect_name(data: &[u8]) -> Option<String> {
    if data.len() < 20 || data[0] != 0x82 { return None; }
    let ws_hdr = if data[1] < 126 { 2 } else if data[1] == 126 { 4 } else { return None };
    let p = ws_hdr;
    if p + 12 > data.len() || data[p] != 0x80 { return None; }
    let psd_len = data[p + 1] as usize;
    let rmc = p + 12 + psd_len;
    if rmc + 14 > data.len() { return None; }
    let ms = rmc + 14;
    let max_p_off = ms + 5 + 4 + 8 + 8 + 2;
    if max_p_off + 2 > data.len() { return None; }
    let mut o = max_p_off + 2 + 4 + 4 + 4 + 4;
    if o + 2 > data.len() { return None; }
    let desc_len = u16::from_le_bytes([data[o], data[o + 1]]) as usize;
    o += 2 + desc_len;
    o += 5 + 4;
    if o + 4 > data.len() { return None; }
    let attr_count = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
    o += 4 + attr_count * 4;
    o += 1 + 4;
    if o + 4 > data.len() { return None; }
    let app_buf_len = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
    o += 4;
    if app_buf_len < 0x20 || o + 0x20 > data.len() { return None; }
    let name_off = o + 0x1e;
    let mut u16s = Vec::new();
    let mut i = name_off;
    while i + 1 < data.len() && u16s.len() < 20 {
        let c = u16::from_le_bytes([data[i], data[i + 1]]);
        if c == 0 { break; }
        u16s.push(c);
        i += 2;
    }
    if u16s.is_empty() { return None; }
    Some(String::from_utf16_lossy(&u16s))
}

// rewrite the method 40 response in place: pretend we're the host and trash the key.
// game stays on the training stage and kicks off a new search.
// returns false on malformed buffers, caller falls back to blocking recvfrom
#[cfg(feature = "avaru-guard")]
unsafe fn masquerade_as_self_host(buf: *mut u8, size: usize) -> bool {
    use crate::net::nex::MY_PID;
    // TODO: grab this from proto=10 LoginEx so we don't need a hardcoded fallback
    // const HARDCODED_MY_PID: u64 = 121507894249139967;
    let my_pid = MY_PID.load(std::sync::atomic::Ordering::SeqCst);
    if my_pid == 0 {
        // my_pid = HARDCODED_MY_PID;
        // MY_PID.store(my_pid, std::sync::atomic::Ordering::SeqCst);
        // bail out so caller falls back to blocking recvfrom
        return false;
    }
    let data = std::slice::from_raw_parts_mut(buf, size);
    let ws_hdr = if data[1] < 126 { 2usize } else { 4usize };
    let p = ws_hdr;
    let psd_len = data[p + 1] as usize;
    let rmc = p + 12 + psd_len;
    let ms = rmc + 14;
    // Gathering: header(5) + id(4) + owner(8) + host(8)
    let owner_off = ms + 5 + 4;
    let host_off = owner_off + 8;
    if host_off + 8 > size { return false; }
    // stash the original owner for the blocklist learner
    let original_owner = u64::from_le_bytes(
        data[owner_off..owner_off + 8].try_into().unwrap()
    );
    LAST_MASQ_ORIGINAL_OWNER.store(original_owner, std::sync::atomic::Ordering::SeqCst);
    let pid_bytes = my_pid.to_le_bytes();
    data[owner_off..owner_off + 8].copy_from_slice(&pid_bytes);
    data[host_off..host_off + 8].copy_from_slice(&pid_bytes);

    if let Some(new_max) = MASQ_MAX_PARTICIPANTS {
        let max_p_off = host_off + 8 + 2;
        if max_p_off + 2 <= size {
            data[max_p_off..max_p_off + 2].copy_from_slice(&new_max.to_le_bytes());
        }
    }
    if let Some(new_state) = MASQ_STATE {
        let state_off = host_off + 8 + 2 + 2 + 4 + 4 + 4;
        if state_off + 4 <= size {
            data[state_off..state_off + 4].copy_from_slice(&new_state.to_le_bytes());
        }
    }

    // skip min_p/max_p/policy/arg/flags/state (2+2+4+4+4+4), then description
    let mut o = host_off + 8 + 2 + 2 + 4 + 4 + 4 + 4;
    if o + 2 > size { return false; }
    let desc_len = u16::from_le_bytes([data[o], data[o + 1]]) as usize;
    o += 2 + desc_len;
    // MatchmakeSession header(5) + game_mode(4)
    o += 5 + 4;
    if o + 4 > size { return false; }
    let attr_count = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
    o += 4 + attr_count * 4;
    o += 1 + 4; // open_participation + matchmake_system_type
    if o + 4 > size { return false; }
    let app_buf_len = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
    o += 4;
    // app_buf[0] = 0x01 flags us as the host
    if app_buf_len > 0 && o < size {
        data[o] = 0x01;
    }
    // skip the rest of app_buf, then participation_count(4) + progress_score(1)
    o += app_buf_len;
    if o + 4 <= size {
        data[o..o + 4].copy_from_slice(&MASQ_PARTICIPATION_COUNT.to_le_bytes());
    }
    o += 4 + 1;
    // session_key: u32 len + bytes. zero it so pia can't complete key exchange
    if o + 4 > size { return false; }
    let key_len = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
    o += 4;
    if o + key_len > size { return false; }
    for i in 0..key_len {
        data[o + i] = 0x00;
    }
    true
}

// --- hooks ---

#[skyline::hook(replace = ssl_create)]
unsafe fn hook_ssl_create(this: u64, context: u64) -> i32 {
    let ret = call_original!(this, context);
    INITIAL_CONN.compare_exchange(0, this, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst).ok();
    #[cfg(feature = "avaru-guard")]
    {
        crate::net::socket::BLOCK_FIRST.store(false, std::sync::atomic::Ordering::SeqCst);
        crate::net::socket::BLOCK_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        crate::net::socket::SUPPRESS_ERROR.store(false, std::sync::atomic::Ordering::SeqCst);
        crate::net::socket::SUPPRESS_GAME_ERROR.store(false, std::sync::atomic::Ordering::SeqCst);
    }
    ret
}

#[skyline::hook(replace = ssl_read)]
unsafe fn hook_ssl_read(this: u64, buf: *mut u8, out_size: *mut i32, len: u32) -> i32 {
    let ret = call_original!(this, buf, out_size, len);
    let conn = INITIAL_CONN.load(std::sync::atomic::Ordering::SeqCst);
    if conn == 0 || this != conn { return ret; }
    if buf.is_null() || out_size.is_null() || *out_size <= 0 { return ret; }

    let data = std::slice::from_raw_parts_mut(buf, *out_size as usize);

    #[cfg(feature = "avaru-guard")]
    if let Some(Some(_reason)) = quick_detect_suspect(data) {
        // grab the name before masquerade clobbers the buffer
        let suspect_name = extract_suspect_name(data).unwrap_or_default();
        if masquerade_as_self_host(buf, *out_size as usize) {
            MASQUERADE_APPLIED.store(true, std::sync::atomic::Ordering::SeqCst);
        } else {
            crate::net::socket::BLOCK_FIRST.store(true, std::sync::atomic::Ordering::SeqCst);
            crate::net::socket::BLOCK_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        }
        crate::ui::notify::show_cheater_blocked(&suspect_name);
    }

    push_read(Role::Client, data);

    ret
}

#[skyline::hook(replace = ssl_write)]
unsafe fn hook_ssl_write(this: u64, buf: *const u8, out_size: *mut i32, len: usize) -> i32 {
    let ret = call_original!(this, buf, out_size, len);
    let conn = INITIAL_CONN.load(std::sync::atomic::Ordering::SeqCst);
    if conn == 0 || this != conn { return ret; }
    if buf.is_null() || out_size.is_null() || *out_size <= 0 { return ret; }
    let data = std::slice::from_raw_parts(buf, *out_size as usize);
    push_read(Role::Server, data);
    ret
}

pub fn install() {
    skyline::install_hooks!(hook_ssl_create, hook_ssl_read, hook_ssl_write);
}
