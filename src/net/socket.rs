use skyline::libc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::net::pia;

pub static P2P_PEER_IP: AtomicU32 = AtomicU32::new(0);
pub static P2P_PEER_PORT: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "avaru-guard")]
pub static BLOCK_FIRST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "avaru-guard")]
pub static BLOCK_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "avaru-guard")]
pub static SUPPRESS_ERROR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "avaru-guard")]
pub static SUPPRESS_GAME_ERROR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
// ip:port dedupe. 4/4 cheaters can give us 8+ peers so 16 slots
static KNOWN_PEERS: [AtomicU64; 16] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];
pub static SERVER_IP: AtomicU32 = AtomicU32::new(0);
pub static BIND_PORT: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SockaddrIn {
    pub sin_len: u8,
    pub sin_family: u8,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

pub fn format_ip(ip_nbo: u32) -> String {
    let b = ip_nbo.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

// nex sticks to fixed server ports, filter them out so we only see p2p (pia)
fn is_server_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443)
}

fn extract_addr(addr: *const libc::sockaddr) -> Option<(u32, u16)> {
    if addr.is_null() { return None; }
    unsafe {
        let sa = addr as *const SockaddrIn;
        let ip = (*sa).sin_addr;
        let port = u16::from_be((*sa).sin_port);
        if ip == 0 { return None; }
        Some((ip, port))
    }
}

extern "C" {
    // pia udp slips past nn::socket::*, hook the detail:: variant to catch it
    #[link_name = "_ZN2nn6socket6detail8RecvFromEiPvmNS0_7MsgFlagEPNS0_8SockAddrEPj"]
    fn detail_recvfrom(
        fd: i32, buf: *mut u8, len: u64, flags: i32,
        addr: *mut libc::sockaddr, addr_len: *mut u32,
    ) -> i64;

    #[link_name = "_ZN2nn6socket6detail4BindEiPKNS0_8SockAddrEj"]
    fn detail_bind(fd: i32, addr: *const libc::sockaddr, addr_len: u32) -> i32;
}

#[skyline::hook(replace = detail_recvfrom)]
unsafe fn hook_recvfrom(
    fd: i32, buf: *mut u8, len: u64, flags: i32,
    addr: *mut libc::sockaddr, addr_len: *mut u32,
) -> i64 {
    // fallback when masquerade fails: starve pia until it times out.
    // don't close the socket, that breaks pia for good
    #[cfg(feature = "avaru-guard")]
    if BLOCK_FIRST.load(Ordering::Relaxed) {
        let n = BLOCK_COUNT.fetch_add(1, Ordering::Relaxed);
        if n == 0 {
        }
        if n == 50 {
            SUPPRESS_ERROR.store(true, Ordering::SeqCst);
            SUPPRESS_GAME_ERROR.store(true, Ordering::SeqCst);
            // nex goes over websocket on a different path, leave it alive
            crate::game::SUPPRESSED.store(true, Ordering::SeqCst);
        }
        return -1;
    }
    let ret = call_original!(fd, buf, len, flags, addr, addr_len);
    if ret <= 0 { return ret; }

    if let Some((ip, port)) = extract_addr(addr as *const _) {
        let first_octet = ip.to_be_bytes()[0];
        if first_octet != 127 && !is_server_port(port) {
            P2P_PEER_IP.store(ip, Ordering::Relaxed);
            P2P_PEER_PORT.store(port as u32, Ordering::Relaxed);
            let key = ((ip as u64) << 16) | port as u64;
            let known = KNOWN_PEERS.iter().any(|p| p.load(Ordering::Relaxed) == key);
            if !known {
                for slot in &KNOWN_PEERS {
                    if slot.compare_exchange(0, key, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                        break;
                    }
                }
            }
        } else if is_server_port(port) {
            SERVER_IP.store(ip, Ordering::Relaxed);
        }
    }

    // hand the raw udp payload off to pia for decrypt
    let data = std::slice::from_raw_parts(buf, ret as usize);
    pia::push_packet(data);

    ret
}

#[skyline::hook(replace = detail_bind)]
unsafe fn hook_bind(fd: i32, addr: *const libc::sockaddr, addr_len: u32) -> i32 {
    let ret = call_original!(fd, addr, addr_len);
    if let Some((_, port)) = extract_addr(addr) {
        BIND_PORT.store(port as u32, Ordering::Relaxed);
    }
    ret
}

pub fn reset_known_peers() {
    for slot in &KNOWN_PEERS {
        slot.store(0, Ordering::Relaxed);
    }
}

pub fn install() {
    skyline::install_hooks!(hook_recvfrom, hook_bind);
}
