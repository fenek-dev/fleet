//! Noise transport after a fixed XX handshake: arbitrary ciphertexts into
//! `decrypt` (must fail cleanly), and plaintext records round-trip.
//! Input: records `len: u8 ‖ bytes[len]`; odd records are sent as forged
//! ciphertext, even ones are encrypted by the peer first.
#![no_main]

use std::sync::{LazyLock, Mutex};

use fleet_crypto::Zeroizing;
use fleet_crypto::noise::{Handshake, StaticKeypair, Transport, prologue};
use libfuzzer_sys::fuzz_target;

fn pair() -> (Transport, Transport) {
    let a = StaticKeypair::from_bytes(&Zeroizing::new([0x11; 32]));
    let b = StaticKeypair::from_bytes(&Zeroizing::new([0x22; 32]));
    let p = prologue(0);
    let mut i = Handshake::initiator(&a, &p).unwrap();
    let mut r = Handshake::responder(&b, &p).unwrap();
    let m1 = i.write_message(&[]).unwrap();
    r.read_message(&m1).unwrap();
    let m2 = r.write_message(&[]).unwrap();
    i.read_message(&m2).unwrap();
    let m3 = i.write_message(&[]).unwrap();
    r.read_message(&m3).unwrap();
    (i.into_transport(0).unwrap(), r.into_transport(0).unwrap())
}

// One handshake per process (X25519 dominates otherwise); the pair keeps
// its nonces across inputs, which the checks below don't depend on.
static PAIR: LazyLock<Mutex<(Transport, Transport)>> = LazyLock::new(|| Mutex::new(pair()));

fuzz_target!(|data: &[u8]| {
    let mut guard = PAIR.lock().unwrap_or_else(|e| e.into_inner());
    let (tx, rx) = &mut *guard;
    let mut rest = data;
    let mut n = 0usize;
    while let Some((&len, tail)) = rest.split_first() {
        let k = (len as usize).min(tail.len());
        let (rec, tail) = tail.split_at(k);
        rest = tail;
        n += 1;
        if n % 2 == 1 {
            // Forged ciphertext: must be rejected (a 16-byte tag can't be
            // guessed), and must not desync the next honest message.
            assert!(rx.decrypt(rec).is_err(), "forged message accepted");
        } else {
            let ct = tx.encrypt(rec).unwrap();
            assert_eq!(rx.decrypt(&ct).unwrap(), rec);
        }
    }
});
