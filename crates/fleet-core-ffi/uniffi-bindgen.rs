//! `uniffi-bindgen` pinned to this workspace's `uniffi` version. Used in
//! library mode by `scripts/build-core.sh`.
#![forbid(unsafe_code)]

fn main() {
    uniffi::uniffi_bindgen_main()
}
