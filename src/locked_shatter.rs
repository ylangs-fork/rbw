//! In-memory wrapping for the user key.
//!
//! This is deliberately an obfuscation layer rather than a boundary against a
//! targeted privileged attacker: all shares remain in the same process.  Its
//! purpose is to keep the complete plaintext key out of long-lived memory and
//! defeat generic scanners that only look for a contiguous key-shaped value.

use rand::TryRngCore as _;
use zeroize::Zeroizing;

const MATERIAL_LEN: usize = crate::locked::KEYS_LEN;

/// A two-share XOR split stored in distinct, memory-locked heap allocations.
struct SplitSecret {
    first: Box<crate::locked::Vec>,
    second: Box<crate::locked::Vec>,
}

impl SplitSecret {
    fn from_secret(secret: &[u8; MATERIAL_LEN]) -> Self {
        let mut first = Zeroizing::new([0_u8; MATERIAL_LEN]);
        rand::rngs::OsRng
            .try_fill_bytes(first.as_mut())
            .expect("operating-system randomness unavailable");
        let mut second = Zeroizing::new([0_u8; MATERIAL_LEN]);
        for (out, (left, value)) in
            second.iter_mut().zip(first.iter().zip(secret.iter()))
        {
            *out = left ^ value;
        }

        Self {
            first: Box::new(locked_vec(first.iter().copied())),
            second: Box::new(locked_vec(second.iter().copied())),
        }
    }

    fn reconstruct(&self) -> Zeroizing<[u8; MATERIAL_LEN]> {
        let mut secret = Zeroizing::new([0_u8; MATERIAL_LEN]);
        for (out, (left, right)) in secret
            .iter_mut()
            .zip(self.first.data().iter().zip(self.second.data().iter()))
        {
            *out = left ^ right;
        }
        secret
    }
}

fn locked_vec(bytes: impl Iterator<Item = u8>) -> crate::locked::Vec {
    let mut value = crate::locked::Vec::new();
    value.extend(bytes);
    value
}

/// Long-lived, wrapped user-key material.
///
/// The wrapping pad and the wrapped key are each split into two XOR shares,
/// giving four independently allocated, memory-locked buffers.  The complete
/// pad, ciphertext, and user key only coexist during `with_unsealed`.
pub struct ShatteredKeys {
    wrapping_pad: SplitSecret,
    wrapped_key: SplitSecret,
}

impl ShatteredKeys {
    /// Wrap `keys` with a fresh operating-system random pad and split both the
    /// pad and ciphertext into independent XOR shares.
    pub fn seal(keys: &crate::locked::Keys) -> Self {
        let mut wrapping_pad = Zeroizing::new([0_u8; MATERIAL_LEN]);
        rand::rngs::OsRng
            .try_fill_bytes(wrapping_pad.as_mut())
            .expect("operating-system randomness unavailable");
        let mut wrapped_key = Zeroizing::new([0_u8; MATERIAL_LEN]);
        for (out, (plain, pad)) in wrapped_key
            .iter_mut()
            .zip(keys.as_bytes().iter().zip(wrapping_pad.iter()))
        {
            *out = plain ^ pad;
        }

        Self {
            wrapping_pad: SplitSecret::from_secret(&wrapping_pad),
            wrapped_key: SplitSecret::from_secret(&wrapped_key),
        }
    }

    /// Reconstruct the key in a memory-locked buffer for exactly one closure.
    ///
    /// The closure cannot return a reference tied to the temporary key.  The
    /// plaintext is explicitly zeroed both on the normal path and while
    /// unwinding from a panic via `UnsealedGuard::drop`.
    pub fn with_unsealed<R>(
        &self,
        f: impl FnOnce(&crate::locked::Keys) -> R,
    ) -> R {
        let wrapping_pad = self.wrapping_pad.reconstruct();
        let wrapped_key = self.wrapped_key.reconstruct();
        let material = locked_vec(
            wrapped_key
                .iter()
                .zip(wrapping_pad.iter())
                .map(|(wrapped, pad)| wrapped ^ pad),
        );

        let mut guard = UnsealedGuard::new(material);
        let result = f(guard.keys());
        guard.zero_now();
        result
    }

    #[cfg(test)]
    fn allocations_are_distinct(&self) -> bool {
        let allocations = [
            self.wrapping_pad.first.data().as_ptr().addr(),
            self.wrapping_pad.second.data().as_ptr().addr(),
            self.wrapped_key.first.data().as_ptr().addr(),
            self.wrapped_key.second.data().as_ptr().addr(),
        ];
        allocations.iter().enumerate().all(|(index, left)| {
            allocations[index + 1..]
                .iter()
                .all(|right| left.abs_diff(*right) >= MATERIAL_LEN)
        })
    }

    #[cfg(test)]
    fn no_shard_contains(&self, secret: &[u8]) -> bool {
        [
            self.wrapping_pad.first.data(),
            self.wrapping_pad.second.data(),
            self.wrapped_key.first.data(),
            self.wrapped_key.second.data(),
        ]
        .iter()
        .all(|shard| {
            !shard.windows(secret.len()).any(|bytes| bytes == secret)
        })
    }
}

struct UnsealedGuard {
    keys: crate::locked::Keys,
    zeroed: bool,
}

impl UnsealedGuard {
    fn new(material: crate::locked::Vec) -> Self {
        Self {
            keys: crate::locked::Keys::new(material),
            zeroed: false,
        }
    }

    fn keys(&self) -> &crate::locked::Keys {
        &self.keys
    }

    fn zero_now(&mut self) {
        self.keys.zeroize();
        self.zeroed = true;
        #[cfg(test)]
        record_zeroization(self.keys.as_bytes());
    }
}

impl Drop for UnsealedGuard {
    fn drop(&mut self) {
        if !self.zeroed {
            self.keys.zeroize();
            #[cfg(test)]
            record_zeroization(self.keys.as_bytes());
        }
    }
}

#[cfg(test)]
fn record_zeroization(bytes: &[u8]) {
    LAST_TEMPORARY_ZEROED.store(
        bytes.iter().all(|byte| *byte == 0),
        std::sync::atomic::Ordering::SeqCst,
    );
}

#[cfg(test)]
fn reset_zeroization_record() {
    LAST_TEMPORARY_ZEROED.store(false, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
fn temporary_was_zeroized() -> bool {
    LAST_TEMPORARY_ZEROED.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
static ZEROIZATION_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

#[cfg(test)]
static LAST_TEMPORARY_ZEROED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> crate::locked::Keys {
        let mut material = crate::locked::Vec::new();
        material.extend(0_u8..64);
        crate::locked::Keys::new(material)
    }

    #[test]
    fn round_trip_restores_key_and_zeroizes_temporary() {
        let _test_lock = ZEROIZATION_TEST_LOCK.lock().unwrap();
        reset_zeroization_record();
        let original = test_keys();
        let shattered = ShatteredKeys::seal(&original);
        shattered.with_unsealed(|restored| {
            assert_eq!(restored.as_bytes(), original.as_bytes());
        });
        assert!(temporary_was_zeroized());
    }

    #[test]
    fn shards_use_distinct_non_overlapping_allocations() {
        let original = test_keys();
        let shattered = ShatteredKeys::seal(&original);
        assert!(shattered.allocations_are_distinct());
        assert!(shattered.no_shard_contains(original.as_bytes()));
    }

    #[test]
    fn error_result_zeroizes_temporary_plaintext() {
        let _test_lock = ZEROIZATION_TEST_LOCK.lock().unwrap();
        reset_zeroization_record();
        let shattered = ShatteredKeys::seal(&test_keys());
        let result: anyhow::Result<()> = shattered
            .with_unsealed(|_| Err(anyhow::anyhow!("deliberate test error")));
        assert!(result.is_err());
        assert!(temporary_was_zeroized());
    }

    #[test]
    fn panic_path_zeroizes_temporary_plaintext() {
        let _test_lock = ZEROIZATION_TEST_LOCK.lock().unwrap();
        reset_zeroization_record();
        let shattered = ShatteredKeys::seal(&test_keys());
        let panic =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                shattered.with_unsealed(|_| panic!("test panic"));
            }));
        assert!(panic.is_err());
        assert!(temporary_was_zeroized());
    }
}
