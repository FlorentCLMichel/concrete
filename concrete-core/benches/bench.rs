use criterion::{criterion_group, criterion_main, Criterion};

use std::fmt::Debug;

use concrete_commons::parameters::{ LweSize, DecompositionLevelCount, DecompositionBaseLog,
                                    LweDimension, GlweDimension, PolynomialSize };
use concrete_commons::dispersion::LogStandardDev;
use concrete_commons::numeric::{ CastFrom, CastInto, Numeric };

#[cfg(all(feature = "backend_core", not(feature = "backend_optalysys")))]
use concrete_core::backends::core::private::{ crypto::*, math::* };

#[cfg(feature = "backend_optalysys")]
use concrete_core::backends::optalysys::private::{ crypto::*, math::* };

use bootstrap::*;
use secret::{ LweSecretKey, GlweSecretKey };
use secret::generators::{ SecretRandomGenerator, EncryptionRandomGenerator };
use random::RandomGenerator;
use encoding::Plaintext;
use glwe::GlweCiphertext;
use lwe::LweCiphertext;
use fft::Complex64;
use tensor::{ Tensor, AsMutTensor, AsMutSlice, AsRefTensor, AsRefSlice };
use torus::UnsignedTorus;

fn test_bootstrap_drift<T: UnsignedTorus + Debug>()
where
    i64: CastFrom<T>,
{
    // define settings
    let nb_test: usize = 2;
    let polynomial_size = PolynomialSize(1024);
    let rlwe_dimension = GlweDimension(1);
    let lwe_dimension = LweDimension(630);
    let level = DecompositionLevelCount(3);
    let base_log = DecompositionBaseLog(7);
    let std = LogStandardDev::from_log_standard_dev(-29.);
    let log_degree = f64::log2(polynomial_size.0 as f64) as i32;
    let mut random_generator = RandomGenerator::new(None);
    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);

    let mut rlwe_sk =
        GlweSecretKey::generate_binary(rlwe_dimension, polynomial_size, &mut secret_generator);
    let mut lwe_sk = LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

    let mut msg = Tensor::allocate(T::ZERO, nb_test);
    let mut new_msg = Tensor::allocate(T::ZERO, nb_test);

    // launch nb_test tests
    for i in 0..nb_test {
        // fill keys with random
        random_generator.fill_tensor_with_random_uniform_binary(&mut rlwe_sk);
        random_generator.fill_tensor_with_random_uniform_binary(&mut lwe_sk);

        // allocation and generation of the key in coef domain:
        let mut coef_bsk = StandardBootstrapKey::allocate(
            T::ZERO,
            rlwe_dimension.to_glwe_size(),
            polynomial_size,
            level,
            base_log,
            lwe_dimension,
        );
        coef_bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut encryption_generator);

        // allocation for the bootstrapping key
        let mut fourier_bsk = FourierBootstrapKey::allocate(
            Complex64::new(0., 0.),
            rlwe_dimension.to_glwe_size(),
            polynomial_size,
            level,
            base_log,
            lwe_dimension,
        );
        let mut buffers = FourierBskBuffers::new(fourier_bsk.polynomial_size(), fourier_bsk.glwe_size());
        fourier_bsk.fill_with_forward_fourier(&coef_bsk, &mut buffers);

        let val = (polynomial_size.0 as f64 - (10. * f64::sqrt((lwe_dimension.0 as f64) / 16.0)))
            * 2_f64.powi(<T as Numeric>::BITS as i32 - log_degree - 1);
        let val = T::cast_from(val);

        let m0 = Plaintext(val);

        msg.as_mut_slice()[i] = val;

        let mut lwe_in = LweCiphertext::allocate(T::ZERO, lwe_dimension.to_lwe_size());
        let mut lwe_out =
            LweCiphertext::allocate(T::ZERO, LweSize(rlwe_dimension.0 * polynomial_size.0 + 1));
        lwe_sk.encrypt_lwe(&mut lwe_in, &m0, std, &mut encryption_generator);

        // accumulator is a trivial encryption of [0, 1/2N, 2/2N, ...]
        let mut accumulator =
            GlweCiphertext::allocate(T::ZERO, polynomial_size, rlwe_dimension.to_glwe_size());
        accumulator
            .get_mut_body()
            .as_mut_tensor()
            .iter_mut()
            .enumerate()
            .for_each(|(i, a)| {
                *a = (i as f64 * 2_f64.powi(<T as Numeric>::BITS as i32 - log_degree - 1))
                    .cast_into();
            });

        // bootstrap
        let mut buffers =
            FourierBskBuffers::new(fourier_bsk.polynomial_size(), fourier_bsk.glwe_size());
        fourier_bsk.bootstrap(&mut lwe_out, &lwe_in, &accumulator, &mut buffers);

        let mut m1 = Plaintext(T::ZERO);

        // now the lwe is encrypted using a flatten of the trlwe encryption key
        let flattened_key = LweSecretKey::binary_from_container(rlwe_sk.as_tensor().as_slice());
        flattened_key.decrypt_lwe(&mut m1, &lwe_out);
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("core");
    group.significance_level(0.1).sample_size(10);
    group.bench_function("test_bootstrap_drift_u32", |b| b.iter(|| test_bootstrap_drift::<u32>()));
    group.bench_function("test_bootstrap_drift_u64", |b| b.iter(|| test_bootstrap_drift::<u64>()));
    group.finish()
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
