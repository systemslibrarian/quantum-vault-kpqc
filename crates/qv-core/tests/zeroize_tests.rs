// SPDX-License-Identifier: MIT
//! Secret key zeroization tests.
//!
//! Verifies that structs holding secret material implement [`ZeroizeOnDrop`]
//! and that key bytes are overwritten before the backing memory is freed.
//!
//! ## Testing strategy
//!
//! **Raw-pointer tests** use the `Box::into_raw` + `ptr::drop_in_place` pattern:
//!
//! 1. `Box::into_raw` takes ownership of the heap allocation without freeing it.
//! 2. `ptr::drop_in_place` calls the type's `Drop` impl (ZeroizeOnDrop →
//!    `write_volatile` zeros) — but does NOT call `dealloc`.
//! 3. We read via `read_volatile` while the heap allocation is still live.
//! 4. We then reconstruct the `Box` via `Box::from_raw` and drop it normally.
//!
//! This avoids the undefined behaviour of reading already-freed memory, while
//! still observing whether zeroing occurred before the logical destructor returned.
//!
//! ## Caveat
//!
//! The raw-memory check is **best-effort** for `Vec`-backed fields: after the
//! `ZeroizeOnDrop` destructor calls `vec.zeroize()` (which uses `write_volatile`
//! to zero each element), the Vec's internal heap allocation is freed as part of
//! normal field destruction.  For those fields we instead rely on the explicit
//! `.zeroize()` tests (which are non-UB and fully deterministic) plus the
//! compile-time trait-bound assertions.  The primary correctness guarantee
//! comes from `zeroize`'s `write_volatile` use, not from these introspective tests.
//!
//! Run with: `cargo test --test zeroize_tests`

use qv_core::{DecryptOptions, EncryptOptions, KeyShare};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Local test-only struct — stack-allocated bytes, no heap indirection
// ---------------------------------------------------------------------------

/// A minimally-sized secret key struct to test ZeroizeOnDrop on a raw array.
///
/// Using a `[u8; 32]` array (no heap indirection) means the bytes are stored
/// directly in the `Box`'d allocation; `drop_in_place` zeros them while the
/// allocation remains live.
#[derive(Zeroize, ZeroizeOnDrop)]
struct TestSecretKey {
    bytes: [u8; 32],
}

// ---------------------------------------------------------------------------
// 1. Raw-pointer check: TestSecretKey bytes zeroed by ZeroizeOnDrop
// ---------------------------------------------------------------------------

/// `TestSecretKey` bytes are zeroed by `ZeroizeOnDrop` before the allocation is freed.
///
/// Uses `Box::into_raw` + `ptr::drop_in_place` to observe the zeroed bytes
/// while the heap allocation is still live (no UB of reading freed memory).
#[test]
fn test_secret_key_zeroed_on_drop() {
    // Heap-allocate so we can control deallocation timing.
    let boxed = Box::new(TestSecretKey { bytes: [0xAA; 32] });
    let raw = Box::into_raw(boxed); // own heap allocation without freeing it

    // Capture a pointer to the bytes array inside the allocation.
    let data_ptr: *const u8 = unsafe { (*raw).bytes.as_ptr() };

    // Call the destructor — this triggers ZeroizeOnDrop → write_volatile zeros.
    // The allocation is NOT freed (we used into_raw); the bytes remain readable.
    unsafe { std::ptr::drop_in_place(raw) };

    // Verify all bytes are now zero.  The allocation is still live because
    // `into_raw` transferred ownership away from the Box without freeing.
    let all_zero = (0..32).all(|i| unsafe { std::ptr::read_volatile(data_ptr.add(i)) == 0 });

    // Free the allocation (bytes already zeroed; Box<T> doesn't re-run Drop).
    let _ = unsafe { Box::from_raw(raw) };

    assert!(
        all_zero,
        "TestSecretKey bytes should be write_volatile-zeroed by ZeroizeOnDrop"
    );
}

// ---------------------------------------------------------------------------
// 2. Explicit zeroize() call zeroes EncryptOptions::signer_private_key
// ---------------------------------------------------------------------------

/// `EncryptOptions` derives `Zeroize`, so an explicit `.zeroize()` call must
/// sanitize `signer_private_key` in-place (non-UB, fully deterministic).
#[test]
fn encrypt_options_explicit_zeroize_clears_key() {
    let mut opts = EncryptOptions {
        threshold: 2,
        share_count: 2,
        recipient_public_keys: vec![vec![0x01; 32]],
        signer_private_key: vec![0xDE; 32],
    };

    opts.zeroize();

    assert!(
        opts.signer_private_key.iter().all(|&b| b == 0),
        "explicit zeroize() must clear signer_private_key"
    );
    assert!(
        opts.recipient_public_keys
            .iter()
            .all(|k| k.iter().all(|&b| b == 0)),
        "explicit zeroize() must clear recipient_public_keys"
    );
}

// ---------------------------------------------------------------------------
// 3. Explicit zeroize() call zeroes DecryptOptions::recipient_private_keys
// ---------------------------------------------------------------------------

#[test]
fn decrypt_options_explicit_zeroize_clears_keys() {
    let mut opts = DecryptOptions {
        recipient_private_keys: vec![vec![0xEF; 32], vec![0xAB; 32]],
        share_indices: vec![1, 2],
        signer_public_key: vec![0u8; 32],
    };

    opts.zeroize();

    for (i, key) in opts.recipient_private_keys.iter().enumerate() {
        assert!(
            key.iter().all(|&b| b == 0),
            "explicit zeroize() must clear recipient_private_keys[{i}]"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Explicit zeroize() call zeroes KeyShare::data
// ---------------------------------------------------------------------------

#[test]
fn key_share_explicit_zeroize_clears_data() {
    let mut share = KeyShare {
        index: 1,
        data: vec![0xCC; 64],
    };

    share.zeroize();

    assert!(
        share.data.iter().all(|&b| b == 0),
        "explicit zeroize() must clear KeyShare.data"
    );
}

// ---------------------------------------------------------------------------
// 5. Compile-time: ZeroizeOnDrop is implemented for all secret-holding structs
// ---------------------------------------------------------------------------

/// This test is a compile-time assertion.
///
/// If any of these types lose their `ZeroizeOnDrop` derivation, the code
/// below will fail to compile, caught at the `requires_zod` call site.
#[test]
fn structs_implement_zeroize_on_drop() {
    fn requires_zod<T: ZeroizeOnDrop>(_: &T) {}

    let enc_opts = EncryptOptions {
        threshold: 2,
        share_count: 2,
        recipient_public_keys: vec![],
        signer_private_key: vec![],
    };
    requires_zod(&enc_opts);

    let dec_opts = DecryptOptions {
        recipient_private_keys: vec![],
        share_indices: vec![],
        signer_public_key: vec![],
    };
    requires_zod(&dec_opts);

    let share = KeyShare {
        index: 1,
        data: vec![],
    };
    requires_zod(&share);
}

// ---------------------------------------------------------------------------
// 6. Compile-time: Zeroize trait is implemented (explicit call possible)
// ---------------------------------------------------------------------------

/// Ensures all secret-holding types implement `Zeroize` for on-demand clearing.
#[test]
fn structs_implement_zeroize_trait() {
    fn requires_zeroize<T: Zeroize>(_: &mut T) {}

    let mut enc_opts = EncryptOptions {
        threshold: 2,
        share_count: 2,
        recipient_public_keys: vec![],
        signer_private_key: vec![],
    };
    requires_zeroize(&mut enc_opts);

    let mut dec_opts = DecryptOptions {
        recipient_private_keys: vec![],
        share_indices: vec![],
        signer_public_key: vec![],
    };
    requires_zeroize(&mut dec_opts);

    let mut share = KeyShare {
        index: 1,
        data: vec![],
    };
    requires_zeroize(&mut share);
}
