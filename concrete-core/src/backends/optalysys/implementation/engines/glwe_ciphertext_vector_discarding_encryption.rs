use concrete_commons::dispersion::Variance;

use crate::backends::optalysys::implementation::engines::OptalysysEngine;
use crate::backends::optalysys::implementation::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweSecretKey32, GlweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::specification::engines::{
    GlweCiphertextVectorDiscardingEncryptionEngine, GlweCiphertextVectorDiscardingEncryptionError,
};
use crate::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

/// # Description:
/// Implementation of [`GlweCiphertextVectorDiscardingEncryptionEngine`] for [`OptalysysEngine`] that
/// operates on 32 bits integers.
impl
    GlweCiphertextVectorDiscardingEncryptionEngine<
        GlweSecretKey32,
        PlaintextVector32,
        GlweCiphertextVector32,
    > for OptalysysEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// let mut engine = OptalysysEngine::new()?;
    /// let key_1: GlweSecretKey32 =
    ///     engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let key_2: GlweSecretKey32 =
    ///     engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    /// let mut ciphertext_vector =
    ///     engine.encrypt_glwe_ciphertext_vector(&key_1, &plaintext_vector, noise)?;
    ///
    /// engine.discard_encrypt_glwe_ciphertext_vector(
    ///     &key_2,
    ///     &mut ciphertext_vector,
    ///     &plaintext_vector,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(
    /// #     ciphertext_vector.glwe_ciphertext_count(),
    /// #     GlweCiphertextCount(2)
    /// # );
    ///
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(key_1)?;
    /// engine.destroy(key_2)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<(), GlweCiphertextVectorDiscardingEncryptionError<Self::EngineError>> {
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(GlweCiphertextVectorDiscardingEncryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size() != output.polynomial_size() {
            return Err(GlweCiphertextVectorDiscardingEncryptionError::PolynomialSizeMismatch);
        }
        if output.polynomial_size().0 * output.glwe_ciphertext_count().0
            != input.plaintext_count().0
        {
            return Err(GlweCiphertextVectorDiscardingEncryptionError::PlaintextCountMismatch);
        }
        unsafe { self.discard_encrypt_glwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) {
        key.0.encrypt_glwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

/// # Description:
/// Implementation of [`GlweCiphertextVectorDiscardingEncryptionEngine`] for [`OptalysysEngine`] that
/// operates on 64 bits integers.
impl
    GlweCiphertextVectorDiscardingEncryptionEngine<
        GlweSecretKey64,
        PlaintextVector64,
        GlweCiphertextVector64,
    > for OptalysysEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    ///
    /// let mut engine = OptalysysEngine::new()?;
    /// let key_1: GlweSecretKey64 =
    ///     engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let key_2: GlweSecretKey64 =
    ///     engine.create_glwe_secret_key(glwe_dimension, polynomial_size)?;
    /// let plaintext_vector = engine.create_plaintext_vector(&input)?;
    /// let mut ciphertext_vector =
    ///     engine.encrypt_glwe_ciphertext_vector(&key_1, &plaintext_vector, noise)?;
    ///
    /// engine.discard_encrypt_glwe_ciphertext_vector(
    ///     &key_2,
    ///     &mut ciphertext_vector,
    ///     &plaintext_vector,
    ///     noise,
    /// )?;
    /// #
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(
    /// #     ciphertext_vector.glwe_ciphertext_count(),
    /// #     GlweCiphertextCount(2)
    /// # );
    ///
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(key_1)?;
    /// engine.destroy(key_2)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<(), GlweCiphertextVectorDiscardingEncryptionError<Self::EngineError>> {
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(GlweCiphertextVectorDiscardingEncryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size() != output.polynomial_size() {
            return Err(GlweCiphertextVectorDiscardingEncryptionError::PolynomialSizeMismatch);
        }
        if output.polynomial_size().0 * output.glwe_ciphertext_count().0
            != input.plaintext_count().0
        {
            return Err(GlweCiphertextVectorDiscardingEncryptionError::PlaintextCountMismatch);
        }
        unsafe { self.discard_encrypt_glwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn discard_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) {
        key.0.encrypt_glwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}