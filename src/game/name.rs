use skyline::hooks::getRegionAddress;
use std::sync::RwLock;

// two ways to grab player names:
// 1) in-game tag from save data (see azel-s/smash_random_blacklist).
//    pointer chain 0x5314510 -> tag table, tags sit 0xF7D8 apart.
//    update_tag_for_player (0x19fd0b0) maps player_index -> tag_index.
//    doesn't always fire online, depends on the build
// 2) nn::account::GetNickname hook.
//    only fires at boot for the local account, opponents never show up
const OFF_TAG_SAVE: usize = 0x5314510;
const OFF_UPDATE_TAG: usize = 0x19fd0b0;
const TAG_STRIDE: u64 = 0xF7D8;
const TAG_STR_OFF: u64 = 0xC;

static TAG_INDEXES: RwLock<[u8; 8]> = RwLock::new([0; 8]);
pub static LAST_NAMES: RwLock<[Option<String>; 8]> = RwLock::new([None, None, None, None, None, None, None, None]);

#[inline(always)]
fn base() -> usize {
    unsafe { getRegionAddress(skyline::hooks::Region::Text) as usize }
}

pub fn get_tag(tag_index: u8) -> Option<String> {
    unsafe {
        let p0 = *((base() + OFF_TAG_SAVE) as *const u64);
        if p0 == 0 { return None; }
        let p1 = *(p0 as *const u64);
        if p1 == 0 { return None; }
        let p2 = *((p1 + 0x58) as *const u64);
        if p2 == 0 { return None; }
        let p3 = *(p2 as *const u64);
        if p3 == 0 { return None; }

        let tag_addr = (p3 as u64 + (tag_index as u64) * TAG_STRIDE + TAG_STR_OFF) as *const u16;

        let mut len = 0;
        while *tag_addr.add(len) != 0 && len < 32 {
            len += 1;
        }
        if len == 0 { return None; }

        let slice = std::slice::from_raw_parts(tag_addr, len);
        Some(String::from_utf16_lossy(slice))
    }
}

extern "C" {
    // nickname: 33 byte (0x21) null-terminated utf-8, uid: u128 (16 bytes)
    #[link_name = "_ZN2nn7account11GetNicknameEPNS0_8NicknameERKNS0_3UidE"]
    fn nn_account_get_nickname(out: *mut u8, uid: *const u128) -> u32;
}

#[skyline::hook(replace = nn_account_get_nickname)]
unsafe fn hook_get_nickname(out: *mut u8, uid: *const u128) -> u32 {
    let ret = call_original!(out, uid);
    if ret == 0 && !out.is_null() && !uid.is_null() {
        let slice = std::slice::from_raw_parts(out, 33);
        let end = slice.iter().position(|&b| b == 0).unwrap_or(33);
        if let Ok(name) = std::str::from_utf8(&slice[..end]) {
            if !name.is_empty() {
            }
        }
    }
    ret
}

#[skyline::hook(offset = OFF_UPDATE_TAG)]
unsafe fn hook_update_tag(param_1: u64, tag_index: *const u8) {
    let player_idx = *((param_1 + 0x1d4) as *const u8);
    let tag_idx = *tag_index;
    if (player_idx as usize) < 8 {
        if let Ok(mut tags) = TAG_INDEXES.write() {
            tags[player_idx as usize] = tag_idx;
        }
        if let Some(name) = get_tag(tag_idx) {
            if let Ok(mut names) = LAST_NAMES.write() {
                names[player_idx as usize] = Some(name);
            }
        }
    }
    call_original!(param_1, tag_index);
}

pub fn get_player_name(player_idx: usize) -> Option<String> {
    if player_idx >= 8 { return None; }
    LAST_NAMES.read().ok()?.get(player_idx)?.clone()
}

pub fn install() {
    skyline::install_hooks!(hook_get_nickname, hook_update_tag);
}
