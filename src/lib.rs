// spun off from sniffer, stripped most of the logging so unused warnings stick around
#![allow(dead_code, unused_imports, unused_variables)]

mod ansi;
mod net;
mod game;
mod rng;
mod util;
mod ui;

fn panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let loc = info.location().unwrap();
        let msg = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => &s[..],
                None => "Box<Any>",
            },
        };
        let err = format!("panicked at '{}', {}", msg, loc);
        skyline::error::show_error(
            69,
            "ssbu-anti-jp-error panicked. Screenshot this and report.\n",
            err.as_str(),
        );
    }));
}

#[skyline::main(name = "ssbu_anti_jp_error")]
pub fn main() {
    panic_hook();
    net::install();
    game::name::install();
    game::nro::install();
    #[cfg(feature = "avaru-guard")]
    net::nex::load_blocklist();
    unsafe { game::install_scene_hooks(); }
    game::start_poll_thread();
}
