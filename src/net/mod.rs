// data flow:
//   ssl hook        -> copy tls bytes into a ring buffer
//   nex ws thread   -> parse prudp/rmc, pull the session_key
//   socket recvfrom -> pick up udp peers and feed pia
//   pia consumer    -> decrypt with session_key, read rtt

pub mod socket;
pub mod ssl;
pub mod nex;
pub mod pia;

pub fn install() {
    ssl::install();
    nex::start_websocket_threads();
    pia::install();
    socket::install();
}
