use criterion::{criterion_group, criterion_main, Criterion};
use concrete::*;

fn encrypt_bootstrap_decrypt() -> Result<(), CryptoAPIError>
{    
    // encoders
    let encoder_input = Encoder::new(-10., 10., 4, 1)?;
    let encoder_output = Encoder::new(0., 101., 4, 0)?;

    // secret keys
    let sk_rlwe = RLWESecretKey::new(&RLWE128_1024_1);
    let sk_in = LWESecretKey::new(&LWE128_630);
    let sk_out = sk_rlwe.to_lwe_secret_key();

    // bootstrapping key
    let bsk = LWEBSK::new(&sk_in, &sk_rlwe, 5, 3);

    // messages
    let message: f64 = -5.;

    // encode and encrypt
    let c1 = LWE::encode_encrypt(&sk_in, message, &encoder_input)?;

    // bootstrap
    let c2 = c1.bootstrap(&bsk)?;

    // decrypt
    let output = c2.decrypt_decode(&sk_out)?;

    Ok(())
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("concrete");
    group.significance_level(0.1).sample_size(10);
    group.bench_function("encrypt_bootstrap_decrypt", |b| b.iter(|| encrypt_bootstrap_decrypt()));
    group.finish()
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
