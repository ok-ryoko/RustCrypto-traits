use crypto_common::Reset;

use crate::{
    ExtendableOutput,
    ExtendableOutputReset,
    MacError,
    MacMarker,
    Update,
};

/// Convenience wrapper trait covering functionality of message authentication algorithms
/// with customization strings and extendable output
#[cfg_attr(docsrs, doc(cfg(feature = "mac")))]
pub trait MacXof: Sized {
    fn update(&mut self, data: &[u8]);

    #[must_use]
    fn chain_update(self, data: impl AsRef<[u8]>) -> Self;

    fn finalize_xof_into(self, out: &mut [u8])
    where
        Self: ExtendableOutput;

    fn finalize_xof_reset_into(&mut self, out: &mut [u8])
    where
        Self: ExtendableOutputReset;

    fn reset(&mut self)
    where
        Self: Reset;
}

impl<T: Update + ExtendableOutput + MacMarker> MacXof for T {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        Update::update(self, data);
    }

    #[inline]
    fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        Update::update(&mut self, data.as_ref());
        self
    }

    #[inline]
    fn finalize_xof_into(self, out: &mut [u8])
    where
        Self: ExtendableOutput,
    {
        self.finalize_xof_into(out);
    }

    #[inline]
    fn finalize_xof_reset_into(&mut self, out: &mut [u8])
    where
        Self: ExtendableOutputReset,
    {
        self.finalize_xof_reset_into(out);
    }

    #[inline]
    fn reset(&mut self)
    where
        Self: Reset,
    {
        Reset::reset(self)
    }
}
