use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm};
use binrw::{binread, BinRead, BinWrite};
use rtrb::{Consumer, Producer, RingBuffer};
use std::io::{Cursor, Read, Seek};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::net::nex::{GID, SESSION_KEY};

pub static LAST_RTT_US: AtomicU64 = AtomicU64::new(0);

// roll up rtt every 10s. spikes used to print immediately but logs are gone now
const RTT_REPORT_INTERVAL_MS: u128 = 10000;
const RTT_SPIKE_THRESHOLD_MS: u64 = 150;

struct RttWindow {
    samples: Vec<u64>,
    last_report: Instant,
}

impl RttWindow {
    fn new() -> Self {
        Self { samples: Vec::with_capacity(128), last_report: Instant::now() }
    }

    fn push(&mut self, rtt_ms: u64) {
        self.samples.push(rtt_ms);
        if rtt_ms >= RTT_SPIKE_THRESHOLD_MS {
        }
        if self.last_report.elapsed().as_millis() >= RTT_REPORT_INTERVAL_MS {
            self.report();
        }
    }

    fn report(&mut self) {
        if self.samples.is_empty() { return; }
        let n = self.samples.len();
        let _min = *self.samples.iter().min().unwrap();
        let _max = *self.samples.iter().max().unwrap();
        let _avg = self.samples.iter().sum::<u64>() / n as u64;
        self.samples.clear();
        self.last_report = Instant::now();
    }
}

static mut PRODUCER: Option<Producer<Vec<u8>>> = None;
static mut CONSUMER: Option<Consumer<Vec<u8>>> = None;

// called from the recvfrom hook in socket.rs, queues packets for decrypt
pub fn push_packet(data: &[u8]) {
    unsafe {
        if let Some(prod) = &mut *std::ptr::addr_of_mut!(PRODUCER) {
            let _ = prod.push(data.to_vec());
        }
    }
}

fn read_remaining<R: Read + Seek>(r: &mut R, _: binrw::Endian, _: ()) -> binrw::BinResult<Vec<u8>> {
    let mut buf = Vec::new();
    r.read_to_end(&mut buf)?;
    Ok(buf)
}

// pia packet header
#[binread]
#[derive(BinWrite, Debug)]
#[brw(big)]
#[brw(magic = 0x32AB9864u32)]
struct PiaPacket {
    _ver_enc: u8,
    #[br(calc = (_ver_enc & 0x80) >> 7)]
    encrypted: u8,
    #[br(calc = _ver_enc & 0x7F)]
    version: u8,
    connection_id: u8,
    packet_id: u16,
    nonce: u64,
    #[br(count = 16)]
    tag: Vec<u8>,
    #[br(parse_with = read_remaining)]
    messages: Vec<u8>,
}

// pia aes-128-gcm decrypt. iv is connection_id(1) + gid(3) + nonce(8), 12 bytes
fn decrypt(packet: &mut PiaPacket) -> Result<(), ()> {
    let key_guard = SESSION_KEY.read().unwrap();
    let key_bytes = key_guard.as_ref().ok_or(())?;
    if key_bytes.len() < 16 { return Err(()); }

    let gid = GID.load(Ordering::SeqCst);
    let mut iv = [0u8; 12];
    iv[0] = packet.connection_id;
    iv[1..4].copy_from_slice(&gid.to_be_bytes()[1..4]);
    iv[4..12].copy_from_slice(&packet.nonce.to_be_bytes());

    let mut ciphertext = packet.messages.clone();
    ciphertext.extend_from_slice(&packet.tag);

    let cipher = Aes128Gcm::new(aes_gcm::Key::<Aes128Gcm>::from_slice(&key_bytes[..16]));
    packet.messages = cipher
        .decrypt(aes_gcm::Nonce::from_slice(&iv), ciphertext.as_slice())
        .map_err(|_| ())?;
    Ok(())
}

#[derive(Debug)]
struct PiaMessage {
    protocol_type: Option<u8>,
    payload: Vec<u8>,
}

// pia packs multiple messages per packet. flags byte picks a variable header, then payload. 0xFF ends the list
fn parse_messages(raw: &[u8]) -> Vec<PiaMessage> {
    let mut msgs = vec![];
    let mut off = 0;
    let mut protocol_type: Option<u8> = None;
    let mut payload_size: u16 = 0;

    while off < raw.len() {
        let flags = raw[off];
        off += 1;
        if flags == 0xFF { break; }

        if flags & 1 != 0 { off += 1; }
        if flags & 2 != 0 {
            payload_size = u16::from_be_bytes(raw[off..off+2].try_into().unwrap_or([0;2]));
            off += 2;
        }
        if flags & 4 != 0 {
            protocol_type = Some(raw[off]);
            off += 4; // type(1) + port(3)
        }
        if flags & 8 != 0 { off += 8; }
        if flags & 16 != 0 { off += 8; }

        let sz = payload_size as usize;
        let end = (off + sz).min(raw.len());
        msgs.push(PiaMessage { protocol_type, payload: raw[off..end].to_vec() });
        off = end;

        let rem = off % 4;
        if rem != 0 { off += 4 - rem; }
    }
    msgs
}

extern "C" {
    #[link_name = "\u{1}_ZN2nn2os22GetSystemTickFrequencyEv"]
    fn get_tick_freq() -> u64;
}

// proto=0x58 is rtt measurement. type=1 carries the original tick in the response, rtt = now - that
fn try_extract_rtt(msg: &PiaMessage, window: &mut RttWindow) {
    let proto = match msg.protocol_type { Some(p) => p, None => return };
    if proto != 0x58 || msg.payload.len() < 16 { return; }

    let msg_type = u32::from_be_bytes(msg.payload[0..4].try_into().unwrap_or([0;4]));
    if msg_type != 1 { return; }

    let prev_tick = u64::from_be_bytes(msg.payload[8..16].try_into().unwrap_or([0;8]));
    let now = unsafe { skyline::nn::os::GetSystemTick() };
    let freq = unsafe { get_tick_freq() };
    if freq == 0 || prev_tick == 0 { return; }

    let elapsed = now.saturating_sub(prev_tick);
    let rtt_us = (elapsed as f64 / freq as f64 * 1_000_000.0) as u64;
    LAST_RTT_US.store(rtt_us, Ordering::Relaxed);
    window.push(rtt_us / 1000);
}

unsafe fn handle_packet(buf: &[u8], window: &mut RttWindow) {
    let mut packet = match PiaPacket::read(&mut Cursor::new(buf)) {
        Ok(p) => p,
        Err(_) => return,
    };

    if packet.encrypted == 1 {
        if decrypt(&mut packet).is_err() { return; }
    }

    for msg in parse_messages(&packet.messages) {
        try_extract_rtt(&msg, window);
    }
}

fn start_consumer_thread() {
    let consumer = unsafe { (*std::ptr::addr_of_mut!(CONSUMER)).as_mut().expect("consumer not init") };
    std::thread::spawn(move || {
        let mut window = RttWindow::new();
        loop {
            if consumer.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(16));
                continue;
            }
            match consumer.pop() {
                Ok(data) => unsafe { handle_packet(&data, &mut window); },
                Err(_) => {}
            }
        }
    });
}

pub fn install() {
    let (producer, consumer) = RingBuffer::new(256);
    unsafe {
        PRODUCER = Some(producer);
        CONSUMER = Some(consumer);
    }
    start_consumer_thread();
}
