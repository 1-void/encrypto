#![no_main]

use libfuzzer_sys::fuzz_target;
use sequoia_openpgp::parse::Parse;

fuzz_target!(|data: &[u8]| {
    // Exercise basic parsing surfaces (packet header parsing + MPI decoding).
    let _ = sequoia_openpgp::PacketPile::from_bytes(data);
});
