pub mod name;
pub mod nro;

use skyline::hooks::{getRegionAddress, Region};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

extern "C" {
    fn A64HookFunction(symbol: *const (), replace: *const (), result: *mut *const ());
}

use crate::ansi as c;
use crate::net::{socket, pia, nex};

const OFF_STATION_PTR_TABLE: usize = 0x06d42580;
const OFF_STATION_COUNT: usize = 0x06d424a4;
const OFF_PLAYER_ENTRY_MANAGER: usize = 0x052b5fd8;

const OFF_NEX_CONN_CLEANUP: usize = 0x037008d0;
#[cfg(feature = "avaru-guard")]
const OFF_ERROR_DISPATCH: usize = 0x032f1700;
#[cfg(feature = "avaru-guard")]
const OFF_QUICKPLAY_ERROR_HANDLER: usize = 0x01cdd4c8;

const STATION_DATA_BASE: u64 = 0x3E20;
const STATION_DATA_STRIDE: u64 = 0x138;
const MAX_PEERS: usize = 52;
const MAX_PLAYERS: u32 = 16;
const PLAYER_ENTRY_STRIDE: usize = 0x280;

static PREV_HASH: AtomicU64 = AtomicU64::new(0);
static IN_MATCH: AtomicBool = AtomicBool::new(false);
static END_COOLDOWN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static END_PENDING: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[inline(always)]
fn base() -> usize {
    unsafe { getRegionAddress(Region::Text) as usize }
}

pub unsafe fn get_station_count() -> u32 {
    *((base() + OFF_STATION_COUNT) as *const u32)
}

struct RttInfo { avg_ms: f64, max_ms: f64, loss: f64, meas: i64, timeout: i64 }

unsafe fn read_station_rtt(si: usize, pi: usize) -> Option<RttInfo> {
    if pi >= MAX_PEERS { return None; }
    let table = (base() + OFF_STATION_PTR_TABLE) as *const u64;
    let obj = *table.add(si);
    if obj == 0 { return None; }
    let sd = (obj + STATION_DATA_BASE + (pi as u64) * STATION_DATA_STRIDE) as *const i64;
    let cum = *sd;
    let max = *sd.add(1);
    let meas = *sd.add(2);
    let to = *sd.add(3);
    if meas == 0 && to == 0 { return None; }
    let tpm = 19200i64;
    let avg_ms = if meas > 0 { (cum / meas) as f64 / tpm as f64 } else { 0.0 };
    let max_ms = max as f64 / tpm as f64;
    let total = meas + to;
    let loss = if total > 0 { to as f64 / total as f64 } else { 0.0 };
    Some(RttInfo { avg_ms, max_ms, loss, meas, timeout: to })
}

unsafe fn get_player_entry(i: u32) -> Option<*const u8> {
    if i >= MAX_PLAYERS { return None; }
    let a = *((base() + OFF_PLAYER_ENTRY_MANAGER) as *const usize);
    if a == 0 { return None; }
    let b = *(a as *const usize);
    if b == 0 { return None; }
    let arr = *((b + 0x90) as *const usize);
    if arr == 0 { return None; }
    Some((arr + (i as usize) * PLAYER_ENTRY_STRIDE) as *const u8)
}

unsafe fn get_fighter_kind(i: u32) -> Option<u32> {
    let e = get_player_entry(i)?;
    let fk = *(e.add(0x28) as *const u32);
    if fk == 0xFFFFFFFF { None } else { Some(fk) }
}

unsafe fn get_team_id(i: u32) -> i32 {
    get_player_entry(i).map(|e| *(e.add(0xF4) as *const i32)).unwrap_or(-1)
}

unsafe fn get_owner(i: u32) -> i32 {
    get_player_entry(i).map(|e| *(e as *const i32)).unwrap_or(-1)
}

struct PlayerInfo { idx: u32, fighter: u32, owner: i32, team: i32 }

unsafe fn active_players() -> Vec<PlayerInfo> {
    (0..MAX_PLAYERS).filter_map(|i| {
        let fk = get_fighter_kind(i)?;
        let team = get_team_id(i);
        if team < 0 || team >= 4 { return None; }
        Some(PlayerInfo { idx: i, fighter: fk, owner: get_owner(i), team })
    }).collect()
}

pub fn fighter_name(kind: u32) -> &'static str {
    match kind {
        0x00 => "Mario", 0x01 => "Donkey Kong", 0x02 => "Link",
        0x03 => "Samus", 0x04 => "Dark Samus", 0x05 => "Yoshi",
        0x06 => "Kirby", 0x07 => "Fox", 0x08 => "Pikachu",
        0x09 => "Luigi", 0x0A => "Ness", 0x0B => "Captain Falcon",
        0x0C => "Jigglypuff", 0x0D => "Peach", 0x0E => "Daisy",
        0x0F => "Bowser", 0x10 => "Sheik", 0x11 => "Zelda",
        0x12 => "Dr. Mario", 0x13 => "Pichu", 0x14 => "Falco",
        0x15 => "Marth", 0x16 => "Lucina", 0x17 => "Young Link",
        0x18 => "Ganondorf", 0x19 => "Mewtwo", 0x1A => "Roy",
        0x1B => "Chrom", 0x1C => "Mr. Game & Watch",
        0x1D => "Meta Knight", 0x1E => "Pit", 0x1F => "Dark Pit",
        0x20 => "Zero Suit Samus", 0x21 => "Wario", 0x22 => "Snake",
        0x23 => "Ike",
        0x24 => "PT Squirtle", 0x25 => "PT Ivysaur", 0x26 => "PT Charizard",
        0x27 => "Diddy Kong", 0x28 => "Lucas", 0x29 => "Sonic",
        0x2A => "King Dedede", 0x2B => "Olimar", 0x2C => "Lucario",
        0x2D => "R.O.B.", 0x2E => "Toon Link", 0x2F => "Wolf",
        0x30 => "Villager", 0x31 => "Mega Man", 0x32 => "Wii Fit Trainer",
        0x33 => "Rosalina & Luma", 0x34 => "Little Mac", 0x35 => "Greninja",
        0x36 => "Palutena", 0x37 => "Pac-Man", 0x38 => "Robin",
        0x39 => "Shulk", 0x3A => "Bowser Jr.", 0x3B => "Duck Hunt",
        0x3C => "Ryu", 0x3D => "Ken", 0x3E => "Cloud",
        0x3F => "Corrin", 0x40 => "Bayonetta", 0x41 => "Inkling",
        0x42 => "Ridley", 0x43 => "Simon", 0x44 => "Richter",
        0x45 => "King K. Rool", 0x46 => "Isabelle", 0x47 => "Incineroar",
        0x48 => "Mii Brawler", 0x49 => "Mii Swordfighter", 0x4A => "Mii Gunner",
        0x4B => "Popo", 0x4C => "Nana",
        0x4D => "Giga Bowser", 0x4E..=0x50 => "Mii (enemy)",
        0x51 => "Piranha Plant", 0x52 => "Joker", 0x53 => "Hero",
        0x54 => "Banjo & Kazooie", 0x55 => "Terry", 0x56 => "Byleth",
        0x57 => "Min Min", 0x58 => "Steve", 0x59 => "Sephiroth",
        0x5A => "Pyra", 0x5B => "Mythra", 0x5C => "Kazuya", 0x5D => "Sora",
        _ => "Unknown",
    }
}

unsafe fn log_match() {
    let stations = get_station_count();
    let players = active_players();
    let _port = socket::BIND_PORT.load(Ordering::Relaxed);
    let ip = socket::P2P_PEER_IP.load(Ordering::Relaxed);
    let _p = socket::P2P_PEER_PORT.load(Ordering::Relaxed);
    if ip != 0 {
    }
    let _srv = socket::SERVER_IP.load(Ordering::Relaxed);
    let _rtt = pia::LAST_RTT_US.load(Ordering::Relaxed);
    for si in 0..(stations as usize).min(8) {
        for pi in 0..MAX_PEERS {
            if let Some(r) = read_station_rtt(si, pi) {
                if r.meas > 0 {
                    let _lc = if r.loss > 0.05 { c::RED } else { c::GREEN };
                }
            }
        }
    }
    for p in &players {
        let _tag = name::get_player_name(p.idx as usize).map(|n| format!(" \"{}\"", n)).unwrap_or_default();
    }
}

unsafe fn log_state_change() {
    let players = active_players();
    let _chrs: Vec<String> = players.iter().map(|p| format!("p{}={}", p.idx, fighter_name(p.fighter))).collect();
}

unsafe fn state_hash() -> u64 {
    let mut h: u64 = get_station_count() as u64;
    for p in active_players() {
        h = h.wrapping_mul(31).wrapping_add(p.fighter as u64);
        h = h.wrapping_mul(31).wrapping_add(p.idx as u64);
        h = h.wrapping_mul(31).wrapping_add(p.team as u64);
    }
    h = h.wrapping_mul(31).wrapping_add(socket::P2P_PEER_IP.load(Ordering::Relaxed) as u64);
    h
}

static ORIG_NEX_CONN_CLEANUP: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "avaru-guard")]
static ORIG_ERROR_DISPATCH: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "avaru-guard")]
static ORIG_QUICKPLAY_ERROR_HANDLER: AtomicUsize = AtomicUsize::new(0);

// keep nex alive for 30s after a block fires
#[cfg(feature = "avaru-guard")]
pub static SUPPRESSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "avaru-guard")]
static SUPPRESS_CLEANUP_UNTIL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

unsafe extern "C" fn hook_nex_conn_cleanup(this: u64) {
    #[cfg(feature = "avaru-guard")]
    {
        if SUPPRESSED.load(Ordering::Relaxed) {
            SUPPRESSED.store(false, Ordering::SeqCst);
            let deadline = crate::util::now_ms() + 30_000;
            SUPPRESS_CLEANUP_UNTIL.store(deadline, Ordering::SeqCst);
            return;
        }
        let deadline = SUPPRESS_CLEANUP_UNTIL.load(Ordering::Relaxed);
        if deadline > 0 && crate::util::now_ms() < deadline {
            return;
        }
    }
    let orig: extern "C" fn(u64) = std::mem::transmute(ORIG_NEX_CONN_CLEANUP.load(Ordering::SeqCst));
    orig(this);
}

// FUN_01cdd4c8 (state=9 error handler), part of the BLOCK_FIRST fallback
#[cfg(feature = "avaru-guard")]
unsafe extern "C" fn hook_quickplay_error_handler(scene_obj: u64) {
    if socket::SUPPRESS_GAME_ERROR.load(Ordering::Relaxed) {
        socket::SUPPRESS_GAME_ERROR.store(false, Ordering::SeqCst);
        socket::SUPPRESS_ERROR.store(false, Ordering::SeqCst);
        socket::BLOCK_FIRST.store(false, Ordering::SeqCst);
        socket::BLOCK_COUNT.store(0, Ordering::SeqCst);
        return;
    }

    let orig: extern "C" fn(u64) = std::mem::transmute(ORIG_QUICKPLAY_ERROR_HANDLER.load(Ordering::SeqCst));
    orig(scene_obj);
}

// FUN_032f1700 (spawns the error dialog), also part of the BLOCK_FIRST fallback.
// we have to clear BLOCK_FIRST here or recvfrom keeps returning -1 and
// pia dies with 2618-0000 on the next match
#[cfg(feature = "avaru-guard")]
unsafe extern "C" fn hook_error_dialog_setup(param_1: u64, param_2: u64) {
    if socket::SUPPRESS_GAME_ERROR.load(Ordering::Relaxed) {
        socket::SUPPRESS_GAME_ERROR.store(false, Ordering::SeqCst);
        socket::BLOCK_FIRST.store(false, Ordering::SeqCst);
        socket::BLOCK_COUNT.store(0, Ordering::SeqCst);
        return;
    }
    let orig: extern "C" fn(u64, u64) = std::mem::transmute(ORIG_ERROR_DISPATCH.load(Ordering::SeqCst));
    orig(param_1, param_2);
}

#[cfg(feature = "avaru-guard")]
mod show_error {
    
    use crate::net::socket;
    use std::sync::atomic::Ordering;
    extern "C" {
        #[link_name = "_ZN2nn3err9ShowErrorENS_6ResultE"]
        fn nn_err_show_error_result(result: u32);
        #[link_name = "_ZN2nn3err9ShowErrorENS0_9ErrorCodeE"]
        fn nn_err_show_error_code(code: u32);
    }
    #[skyline::hook(replace = nn_err_show_error_result)]
    unsafe fn hook_show_error_result(result: u32) {
        if socket::SUPPRESS_ERROR.load(Ordering::Relaxed) {
            socket::SUPPRESS_ERROR.store(false, Ordering::SeqCst);
            return;
        }
        call_original!(result);
    }
    #[skyline::hook(replace = nn_err_show_error_code)]
    unsafe fn hook_show_error_code(code: u32) {
        if socket::SUPPRESS_ERROR.load(Ordering::Relaxed) {
            socket::SUPPRESS_ERROR.store(false, Ordering::SeqCst);
            return;
        }
        call_original!(code);
    }
    pub fn install() {
        skyline::install_hooks!(hook_show_error_result, hook_show_error_code);
    }
}

pub unsafe fn install_scene_hooks() {
    let b = base();
    let mut orig1: *const () = std::ptr::null();
    A64HookFunction((b + OFF_NEX_CONN_CLEANUP - 0x100) as *const (), hook_nex_conn_cleanup as *const (), &mut orig1 as *mut *const ());
    ORIG_NEX_CONN_CLEANUP.store(orig1 as usize, Ordering::SeqCst);
    #[cfg(feature = "avaru-guard")]
    {
        let mut orig2: *const () = std::ptr::null();
        A64HookFunction((b + OFF_ERROR_DISPATCH - 0x100) as *const (), hook_error_dialog_setup as *const (), &mut orig2 as *mut *const ());
        ORIG_ERROR_DISPATCH.store(orig2 as usize, Ordering::SeqCst);

        let mut orig3: *const () = std::ptr::null();
        A64HookFunction((b + OFF_QUICKPLAY_ERROR_HANDLER - 0x100) as *const (), hook_quickplay_error_handler as *const (), &mut orig3 as *mut *const ());
        ORIG_QUICKPLAY_ERROR_HANDLER.store(orig3 as usize, Ordering::SeqCst);
    }
    #[cfg(feature = "avaru-guard")]
    show_error::install();
}

pub fn start_poll_thread() {
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));

            unsafe {
                let count = get_station_count();
                let players = active_players();
                let hash = state_hash();
                let prev = PREV_HASH.load(Ordering::Relaxed);
                let was = IN_MATCH.load(Ordering::Relaxed);
                let now = count > 0 && players.len() >= 2;
                let cooldown = END_COOLDOWN.load(Ordering::Relaxed);

                if cooldown > 0 {
                    END_COOLDOWN.store(cooldown - 1, Ordering::Relaxed);
                } else if !was && now {
                    END_PENDING.store(0, Ordering::Relaxed);
                    IN_MATCH.store(true, Ordering::Relaxed);
                    nex::mark_match_started();
                    log_match();
                    PREV_HASH.store(hash, Ordering::Relaxed);
                } else if was && !now {
                    let pending = END_PENDING.load(Ordering::Relaxed);
                    if pending >= 1 {
                        IN_MATCH.store(false, Ordering::Relaxed);
                        PREV_HASH.store(0, Ordering::Relaxed);
                        socket::P2P_PEER_IP.store(0, Ordering::Relaxed);
                        socket::P2P_PEER_PORT.store(0, Ordering::Relaxed);
                        socket::reset_known_peers();
                        pia::LAST_RTT_US.store(0, Ordering::Relaxed);
                        #[cfg(feature = "avaru-guard")]
                        nex::SUSPECT.store(false, Ordering::Relaxed);
                        nex::mark_match_started();
                        END_PENDING.store(0, Ordering::Relaxed);
                        END_COOLDOWN.store(8, Ordering::Relaxed);
                    } else {
                        END_PENDING.fetch_add(1, Ordering::Relaxed);
                    }
                } else if was && now {
                    END_PENDING.store(0, Ordering::Relaxed);
                    if hash != prev {
                        log_state_change();
                        PREV_HASH.store(hash, Ordering::Relaxed);
                    }
                } else if now && hash != prev {
                    log_state_change();
                    PREV_HASH.store(hash, Ordering::Relaxed);
                }
            }
        }
    });
}
