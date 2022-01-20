use crate::backends::optalysys::implementation::engines::OptalysysEngine;
use crate::backends::optalysys::implementation::entities::{PlaintextVector32, PlaintextVector64};
use crate::backends::optalysys::private::math::tensor::AsRefTensor;
use crate::specification::engines::{
    PlaintextVectorDiscardingRetrievalEngine, PlaintextVectorDiscardingRetrievalError,
};
use crate::specification::entities::PlaintextVectorEntity;

/// # Description:
/// Implementation of [`PlaintextVectorDiscardingRetrievalEngine`] for [`OptalysysEngine`] that operates
/// on 32 bits integers.
impl PlaintextVectorDiscardingRetrievalEngine<PlaintextVector32, u32> for OptalysysEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::PlaintextCount;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let mut output = vec![0_u32; 3];
    ///
    /// let mut engine = OptalysysEngine::new()?;
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector(&input)?;
    /// engine.discard_retrieve_plaintext_vector(output.as_mut_slice(), &plaintext_vector)?;
    /// #
    /// assert_eq!(output[0], 3_u32 << 20);
    /// engine.destroy(plaintext_vector)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_plaintext_vector(
        &mut self,
        output: &mut [u32],
        input: &PlaintextVector32,
    ) -> Result<(), PlaintextVectorDiscardingRetrievalError<Self::EngineError>> {
        if output.len() != input.plaintext_count().0 {
            return Err(PlaintextVectorDiscardingRetrievalError::PlaintextCountMismatch);
        }
        unsafe { self.discard_retrieve_plaintext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_plaintext_vector_unchecked(
        &mut self,
        output: &mut [u32],
        input: &PlaintextVector32,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}

/// # Description:
/// Implementation of [`PlaintextVectorDiscardingRetrievalEngine`] for [`OptalysysEngine`] that operates
/// on 64 bits integers.
impl PlaintextVectorDiscardingRetrievalEngine<PlaintextVector64, u64> for OptalysysEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::PlaintextCount;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u64 << 20; 3];
    /// let mut output = vec![0_u64; 3];
    ///
    /// let mut engine = OptalysysEngine::new()?;
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector(&input)?;
    /// engine.discard_retrieve_plaintext_vector(output.as_mut_slice(), &plaintext_vector)?;
    /// #
    /// assert_eq!(output[0], 3_u64 << 20);
    /// engine.destroy(plaintext_vector)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_retrieve_plaintext_vector(
        &mut self,
        output: &mut [u64],
        input: &PlaintextVector64,
    ) -> Result<(), PlaintextVectorDiscardingRetrievalError<Self::EngineError>> {
        if output.len() != input.plaintext_count().0 {
            return Err(PlaintextVectorDiscardingRetrievalError::PlaintextCountMismatch);
        }
        unsafe { self.discard_retrieve_plaintext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discard_retrieve_plaintext_vector_unchecked(
        &mut self,
        output: &mut [u64],
        input: &PlaintextVector64,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}
