use std::time::Instant;

static BOOT: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

pub fn now_ms() -> u64 {
    let boot = BOOT.get_or_init(Instant::now);
    boot.elapsed().as_millis() as u64
}

// timestamps like "[+12.345s]"
pub fn ts() -> String {
    let ms = now_ms();
    format!("[+{:>4}.{:03}s]", ms / 1000, ms % 1000)
}
