use std::io::Cursor;
use std::sync::{RwLock, atomic::{AtomicU32, AtomicU64, Ordering}};

use binrw::{binread, BinRead, BinWrite};
use bitflags::bitflags;
use derivative::Derivative;
use num_enum::FromPrimitive;
use tungstenite::{protocol::Role, Message, WebSocket};

use crate::net::ssl::HookedStream;

pub static GID: AtomicU32 = AtomicU32::new(0);
pub static SESSION_KEY: RwLock<Option<Vec<u8>>> = RwLock::new(None); // aes-128 key for pia decrypt
// next 4 are stashed for the phase 4 counter-attack
#[cfg(feature = "avaru-guard")]
pub static LAST_SEARCH_PRUDP_PAYLOAD: RwLock<Option<Vec<u8>>> = RwLock::new(None);
#[cfg(feature = "avaru-guard")]
pub static LAST_SEARCH_PRUDP_HEADER: RwLock<Option<Vec<u8>>> = RwLock::new(None);
#[cfg(feature = "avaru-guard")]
pub static LAST_SEARCH_SEQ_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
#[cfg(feature = "avaru-guard")]
pub static LAST_CALL_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
#[cfg(feature = "avaru-guard")]
pub static SUSPECT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "avaru-guard")]
pub static SUSPECT_SET_TIME: AtomicU64 = AtomicU64::new(0);

static SESSION_REACHED_MATCH: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub static MY_PID: AtomicU64 = AtomicU64::new(0);

// snapshot of whether the last session was masqueraded, gates the auto-learner
#[cfg(feature = "avaru-guard")]
static LAST_SESSION_WAS_MASQUERADED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "avaru-guard")]
static LAST_MASQ_CHEATER_PID: AtomicU64 = AtomicU64::new(0);

// nintendo's prudp lite, runs on top of websocket. starts with 0x80
#[derive(BinRead, BinWrite, Derivative)]
#[derivative(Debug)]
#[br(little)]
#[br(magic = 0x80u8)]
struct PrudpLitePacket {
    psd_len: u8,
    payload_size: u16,
    stream_type: u8,
    source_port: u8,
    destination_port: u8,
    fragment_id: u8,
    types_and_flags: u16,
    sequence_id: u16,
    #[br(count = psd_len)]
    psd: Vec<u8>,
    #[derivative(Debug = "ignore")]
    #[br(count = payload_size)]
    payload: Vec<u8>,
}

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, FromPrimitive)]
enum PacketType {
    Sync = 0, Connect = 1, Data = 2, Disconnect = 3,
    Ping = 4, User = 5, Route = 6, Raw = 7,
    #[num_enum(catch_all)]
    Other(u8),
}

bitflags! {
    #[derive(Debug)]
    struct PacketFlags: u16 {
        const ACK = 0x001;
        const RELIABLE = 0x002;
        const NEED_ACK = 0x004;
        const HAS_SIZE = 0x008;
        const MULTI_ACK = 0x200;
    }
}

#[binread]
#[derive(BinWrite, Debug)]
#[br(little)]
struct RmcPayload {
    size: u32,
    _raw_protocol_id: u8,
    #[brw(temp)]
    #[br(calc = _raw_protocol_id & !0x80)]
    protocol_id_unmasked: u8,
    #[br(if(protocol_id_unmasked == 0x7F))]
    _extended_protocol_id: Option<u16>,
    #[br(calc = _extended_protocol_id.unwrap_or(protocol_id_unmasked as u16))]
    protocol_id: u16,
    // top bit of raw = 1 for request, 0 for response
    #[br(args { _raw_protocol_id, protocol_id })]
    data: RmcData,
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
#[br(import { _raw_protocol_id: u8, protocol_id: u16 })]
enum RmcData {
    #[br(pre_assert(_raw_protocol_id & 0x80 != 0))]
    Request(#[br(args { protocol_id })] RmcRequest),
    #[br(pre_assert(_raw_protocol_id & 0x80 == 0))]
    Response(#[br(args { protocol_id })] RmcResponse),
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
#[br(import { protocol_id: u16 })]
struct RmcRequest {
    call_id: u32,
    method_id: u32,
    // only present for proto=109 method=39 (JoinMatchmakeSessionWithParam)
    #[br(if(protocol_id == 109 && method_id == 39))]
    join_data: Option<JoinMatchmakeSessionData>,
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
struct JoinMatchmakeSessionData {
    header: StructHeader,
    gid: u32,
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
#[br(import { protocol_id: u16 })]
struct RmcResponse {
    status: u8,
    #[br(args { status, protocol_id })]
    result: RmcResult,
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
#[br(import { status: u8, protocol_id: u16 })]
enum RmcResult {
    #[br(pre_assert(status == 0))]
    Error { error_code: u32, call_id: u32 },
    #[br(pre_assert(status != 0))]
    Success(#[br(args { protocol_id })] RmcSuccess),
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
#[br(import { protocol_id: u16 })]
struct RmcSuccess {
    call_id: u32,
    #[br(map(|m: u32| m & !0x8000))]
    method_id: u32,
    #[br(args { protocol_id, method_id })]
    protocol_data: ProtocolData,
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
#[br(import { protocol_id: u16, method_id: u32 })]
enum ProtocolData {
    #[br(pre_assert(protocol_id == 109))]
    Matchmake(#[br(args { method_id })] MatchmakeData),
    Other(()),
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
#[br(import { method_id: u32 })]
enum MatchmakeData {
    // methods 3/38/39/40 return a MatchmakeSession. ssbu elite smash uses 40
    #[br(pre_assert(matches!(method_id, 3 | 38 | 39 | 40)))]
    Session(MatchmakeSession),
    Other(()),
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
struct StructHeader { version: u8, content_length: u32 }

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
struct PrincipalId { id: u64 }

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
struct StringData {
    length: u16,
    #[br(count = length)]
    chars: Vec<u8>,
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
struct ListData<T: for<'a> BinRead<Args<'a> = ()> + for<'a> BinWrite<Args<'a> = ()> + 'static> {
    count: u32,
    #[br(count = count)]
    entries: Vec<T>,
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
struct BufferData {
    length: u32,
    #[br(count = length)]
    bytes: Vec<u8>,
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
struct Gathering {
    header: StructHeader,
    id_myself: u32,          // gathering id
    id_owner: PrincipalId,   // session creator
    id_host: PrincipalId,    // p2p host
    min_participants: u16,
    max_participants: u16,   // 2 for 1v1, cheaters running 4/4 sessions show 4
    participation_policy: u32,
    policy_argument: u32,
    flags: u32,
    state: u32,
    description: StringData,
}

#[derive(BinRead, BinWrite, Debug)]
#[br(little)]
struct MatchmakeSession {
    gathering: Gathering,
    header: StructHeader,
    game_mode: u32,
    attributes: ListData<u32>,      // rules bitfield
    open_participation: u8,
    matchmake_system_type: u32,
    application_buffer: BufferData, // 414 bytes. [0]=0x02 is the cheater tag
    participation_count: u32,
    progress_score: u8,
    session_key: BufferData,        // 32 byte aes-128-gcm key for pia
}

fn extract_utf16_name(buf: &[u8], offset: usize) -> String {
    let mut u16s = vec![];
    let mut i = offset;
    while i + 1 < buf.len() {
        let c = u16::from_le_bytes([buf[i], buf[i + 1]]);
        if c == 0 { break; }
        u16s.push(c);
        i += 2;
        if u16s.len() >= 20 { break; } // safety cap
    }
    String::from_utf16_lossy(&u16s)
}

fn log_rmc(rmc: &RmcPayload) {
    let _t = crate::util::ts();
    match &rmc.data {
        RmcData::Request(_r) => {
        }
        RmcData::Response(r) => match &r.result {
            RmcResult::Success(_s) => {
            }
            RmcResult::Error { error_code: _, call_id: _ } => {
            }
        }
    }
}

fn log_session_info(ms: &MatchmakeSession) {
    let g = &ms.gathering;
    if ms.attributes.count > 0 {
        let _attrs: Vec<String> = ms.attributes.entries.iter().map(|a| a.to_string()).collect();
    }
    #[cfg(feature = "avaru-guard")]
    let masqueraded = crate::net::ssl::MASQUERADE_APPLIED
        .swap(false, Ordering::SeqCst);
    #[cfg(not(feature = "avaru-guard"))]
    let masqueraded = false;

    // snapshot used to decide whether the next session should feed the learner
    #[cfg(feature = "avaru-guard")]
    {
        LAST_SESSION_WAS_MASQUERADED.store(masqueraded, Ordering::SeqCst);
        if masqueraded {
            let cheater = crate::net::ssl::LAST_MASQ_ORIGINAL_OWNER.load(Ordering::SeqCst);
            LAST_MASQ_CHEATER_PID.store(cheater, Ordering::SeqCst);
        } else {
            LAST_MASQ_CHEATER_PID.store(0, Ordering::SeqCst);
        }
    }

    let buf = &ms.application_buffer.bytes;
    if !buf.is_empty() {
        // name sits at app_buf+0x1e as UTF-16LE. app_buf[0]=0x01 means self-hosted so it's our name
        if buf.len() >= 0x20 {
            let name = extract_utf16_name(buf, 0x1e);
            if !name.is_empty() {
            }
        }
        for (_i, _chunk) in buf.chunks(32).enumerate() {
        }
    }
    #[cfg(feature = "avaru-guard")]
    detect_suspect(ms);
}

#[cfg(feature = "avaru-guard")]
mod blocklist {
    use std::sync::RwLock;
    use std::collections::HashSet;

    const BLOCKLIST_PATH: &str = "sd:/atmosphere/contents/01006A800016E000/blocked_pids.txt";

    static PIDS: RwLock<Option<HashSet<u64>>> = RwLock::new(None);

    pub fn load() {
        let mut set = HashSet::new();
        // entries come from the sd card file, grown at runtime by the learner
        if let Ok(data) = std::fs::read_to_string(BLOCKLIST_PATH) {
            for line in data.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                if let Ok(pid) = line.parse::<u64>() {
                    set.insert(pid);
                }
            }
        }
        let _n = set.len();
        *PIDS.write().unwrap() = Some(set);
    }

    pub fn contains(pid: u64) -> bool {
        PIDS.read().ok()
            .and_then(|g| g.as_ref().map(|s| s.contains(&pid)))
            .unwrap_or(false)
    }

    pub fn add(pid: u64) {
        let added = {
            let mut guard = PIDS.write().unwrap();
            let set = guard.get_or_insert_with(HashSet::new);
            set.insert(pid)
        };
        if added {
            save();
        }
    }

    fn save() {
        let guard = PIDS.read().unwrap();
        if let Some(set) = guard.as_ref() {
            let mut lines: Vec<String> = set.iter().map(|p| p.to_string()).collect();
            lines.sort();
            let data = lines.join("\n") + "\n";
            let _ = std::fs::write(BLOCKLIST_PATH, data);
        }
    }
}

#[cfg(feature = "avaru-guard")]
static LAST_SUSPECT_OWNER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(feature = "avaru-guard")]
fn detect_suspect(ms: &MatchmakeSession) {
    let g = &ms.gathering;

    SUSPECT.store(false, std::sync::atomic::Ordering::SeqCst);
    LAST_SUSPECT_OWNER.store(0, std::sync::atomic::Ordering::SeqCst);

    let mut reason: Option<&str> = None;

    // app_buf[0]==0x02 shows up for both 2/2 and 4/4 cheater variants, never in normal play
    if ms.application_buffer.bytes.first() == Some(&0x02) {
        reason = Some("app_buf[0]=0x02");
    }
    if g.max_participants > 2 {
        reason = Some("max_participants > 2");
    }
    if blocklist::contains(g.id_owner.id) {
        reason = Some("blocked PID");
    }
    if blocklist::contains(g.id_host.id) && reason.is_none() {
        reason = Some("blocked PID (host)");
    }

    if let Some(_r) = reason {
        SUSPECT.store(true, std::sync::atomic::Ordering::SeqCst);
        SUSPECT_SET_TIME.store(crate::util::now_ms(), Ordering::SeqCst);
        LAST_SUSPECT_OWNER.store(g.id_owner.id, std::sync::atomic::Ordering::SeqCst);
    }
}

// learn the owner pid from a session that never reached a match
#[cfg(feature = "avaru-guard")]
pub fn learn_failed_session(owner_pid: u64) {
    if owner_pid == 0 { return; }
    let my = MY_PID.load(Ordering::SeqCst);
    if my != 0 && owner_pid == my { return; } // don't block ourselves
    blocklist::add(owner_pid);
}

fn store_session_key(rmc: RmcPayload) {
    match rmc.data {
        RmcData::Request(ref r) => {
            if let Some(ref d) = r.join_data {
                GID.store(d.gid, Ordering::SeqCst);
            }
        }
        RmcData::Response(ref r) => {
            if let RmcResult::Success(ref s) = r.result {
                if let ProtocolData::Matchmake(MatchmakeData::Session(ref ms)) = s.protocol_data {
                    // only learn from sessions we actually masqueraded.
                    // without this, regular cancels trip the learner
                    #[cfg(feature = "avaru-guard")]
                    {
                        let was_masq = LAST_SESSION_WAS_MASQUERADED.load(Ordering::SeqCst);
                        let cheater_pid = LAST_MASQ_CHEATER_PID.load(Ordering::SeqCst);
                        if was_masq && cheater_pid != 0 && !SESSION_REACHED_MATCH.load(Ordering::SeqCst) {
                            learn_failed_session(cheater_pid);
                        }
                    }
                    // at participants=1 we're the owner, so we can read our own pid
                    if ms.participation_count <= 1 && MY_PID.load(Ordering::SeqCst) == 0 {
                        MY_PID.store(ms.gathering.id_owner.id, Ordering::SeqCst);
                    }
                    SESSION_REACHED_MATCH.store(false, Ordering::SeqCst);
                    crate::net::socket::reset_known_peers(); // new session, wipe the peer list

                    log_session_info(ms);
                    GID.store(ms.gathering.id_myself, Ordering::SeqCst);
                    if !ms.session_key.bytes.is_empty() {
                        let mut key = SESSION_KEY.write().unwrap();
                        *key = Some(ms.session_key.bytes.clone());
                    }
                }
            }
        }
    }
}

unsafe fn handle_nex_payload(buf: &[u8], frag_buf: &mut Vec<u8>) {
    let packet = match PrudpLitePacket::read(&mut Cursor::new(buf)) {
        Ok(p) => p,
        Err(_) => return,
    };
    let flags = PacketFlags::from_bits_truncate(packet.types_and_flags >> 4);
    let ptype = PacketType::from((packet.types_and_flags & 0xF) as u8);

    if ptype != PacketType::Data || !flags.contains(PacketFlags::RELIABLE) { return; }

    // remember the seq_id of this reliable DATA packet
    #[cfg(feature = "avaru-guard")]
    LAST_SEARCH_SEQ_ID.store(packet.sequence_id, Ordering::SeqCst);

    // fragment_id == 0 marks the last fragment, keep stacking until then
    let frag_id_was = packet.fragment_id;
    let psd_len_was = packet.psd_len;
    let payload_size_was = packet.payload_size;
    let stream_type_was = packet.stream_type;
    let src_port_was = packet.source_port;
    let dst_port_was = packet.destination_port;
    let type_flags_was = packet.types_and_flags;
    let seq_was = packet.sequence_id;
    let psd_was = packet.psd.clone();
    frag_buf.extend(packet.payload);
    if frag_id_was != 0 { return; }

    // save the proto=109 method=40 request for phase 4 replay
    #[cfg(feature = "avaru-guard")]
    if frag_buf.len() >= 14 {
        let raw_proto = frag_buf[4];
        let is_request = raw_proto & 0x80 != 0;
        let proto_id = raw_proto & 0x7F;
        if is_request && proto_id == 0x6D {
            let method_id = u32::from_le_bytes([frag_buf[9], frag_buf[10], frag_buf[11], frag_buf[12]]);
            if method_id == 40 {
                *LAST_SEARCH_PRUDP_PAYLOAD.write().unwrap() = Some(frag_buf.clone());
                // rebuild the prudp header
                let mut hdr = Vec::with_capacity(12 + psd_len_was as usize);
                hdr.push(0x80);
                hdr.push(psd_len_was);
                hdr.extend_from_slice(&payload_size_was.to_le_bytes());
                hdr.push(stream_type_was);
                hdr.push(src_port_was);
                hdr.push(dst_port_was);
                hdr.push(0x00); // fragment_id
                hdr.extend_from_slice(&type_flags_was.to_le_bytes());
                hdr.extend_from_slice(&seq_was.to_le_bytes());
                hdr.extend_from_slice(&psd_was);
                *LAST_SEARCH_PRUDP_HEADER.write().unwrap() = Some(hdr);
            }
        }
    }

    // track the highest call_id we've seen on client requests
    #[cfg(feature = "avaru-guard")]
    if frag_buf.len() >= 9 && (frag_buf[4] & 0x80) != 0 {
        let cid = u32::from_le_bytes([frag_buf[5], frag_buf[6], frag_buf[7], frag_buf[8]]);
        let prev = LAST_CALL_ID.load(Ordering::SeqCst);
        if cid > prev { LAST_CALL_ID.store(cid, Ordering::SeqCst); }
    }

    let _ = RmcPayload::read(&mut Cursor::new(frag_buf.as_slice()))
        .map(|p| { log_rmc(&p); store_session_key(p); });
    frag_buf.clear();
}

fn websocket_thread(role: Role) {
    std::thread::spawn(move || {
        let mut frag_buf = vec![];
        loop {
            let stream = HookedStream::new(role);
            let mut ws = WebSocket::from_raw_socket(stream, role, None);

            let mut alive = true;
            while alive {
                match ws.read() {
                    Ok(Message::Binary(msg)) => {
                        unsafe { handle_nex_payload(msg.iter().as_slice(), &mut frag_buf); }
                    }
                    Ok(_) => {}
                    Err(tungstenite::Error::Io(ref e))
                        if e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                    Err(_) => { alive = false; }
                }
            }
        }
    });
}

pub fn mark_match_started() {
    SESSION_REACHED_MATCH.store(true, Ordering::SeqCst);
}

#[cfg(feature = "avaru-guard")]
pub fn load_blocklist() {
    blocklist::load();
}

pub fn start_websocket_threads() {
    websocket_thread(Role::Server);
    websocket_thread(Role::Client);
}
