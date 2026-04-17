use getrandom::register_custom_getrandom;

fn switch_getrandom(dest: &mut [u8]) -> Result<(), getrandom::Error> {
    // tegra x1 has no FEAT_RNG, fake it with system ticks.
    // only feeds the tungstenite ws key, nothing crypto
    let mut pos = 0;
    while pos < dest.len() {
        let tick = unsafe { skyline::nn::os::GetSystemTick() };
        let bytes = tick.to_le_bytes();
        let n = (dest.len() - pos).min(8);
        dest[pos..pos + n].copy_from_slice(&bytes[..n]);
        pos += n;
    }
    Ok(())
}

register_custom_getrandom!(switch_getrandom);
