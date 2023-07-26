use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::RistrettoPoint as Point;
use curve25519_dalek::Scalar;
use digest::Digest;
use rand_chacha::ChaCha12Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::Sha512;

use juicebox_sdk_marshalling as marshalling;
use juicebox_sdk_voprf as voprf;

pub fn sha512_bench(c: &mut Criterion) {
    c.bench_function("SHA-512/117 bytes", |b| {
        let mut bytes = [0u8; 117];
        OsRng.fill_bytes(&mut bytes);
        b.iter(|| Sha512::digest(black_box(bytes)))
    });

    c.bench_function("SHA-512/128 bytes", |b| {
        let mut bytes = [0u8; 128];
        OsRng.fill_bytes(&mut bytes);
        b.iter(|| Sha512::digest(black_box(bytes)))
    });

    c.bench_function("SHA-512/181 bytes", |b| {
        let mut bytes = [0u8; 181];
        OsRng.fill_bytes(&mut bytes);
        b.iter(|| Sha512::digest(black_box(bytes)))
    });
}

pub fn curve25519_bench(c: &mut Criterion) {
    c.bench_function("curve25519/scalar-scalar add", |b| {
        let scalar1 = Scalar::random(&mut OsRng);
        let scalar2 = Scalar::random(&mut OsRng);
        b.iter(|| black_box(scalar1) + black_box(scalar2))
    });

    c.bench_function("curve25519/scalar-scalar multiply", |b| {
        let scalar1 = Scalar::random(&mut OsRng);
        let scalar2 = Scalar::random(&mut OsRng);
        b.iter(|| black_box(scalar1) * black_box(scalar2))
    });

    c.bench_function("curve25519/Scalar::invert", |b| {
        let scalar = Scalar::random(&mut OsRng);
        b.iter(|| black_box(scalar).invert())
    });

    c.bench_function("curve25519/point-point add", |b| {
        let point1 = Point::random(&mut OsRng);
        let point2 = Point::random(&mut OsRng);
        b.iter(|| black_box(point1) + black_box(point2))
    });

    c.bench_function("curve25519/scalar-base multiply", |b| {
        let scalar = Scalar::random(&mut OsRng);
        b.iter(|| black_box(Point::mul_base(black_box(&scalar))))
    });

    c.bench_function("curve25519/scalar-point multiply", |b| {
        let scalar = Scalar::random(&mut OsRng);
        let point = Point::random(&mut OsRng);
        b.iter(|| black_box(scalar) * black_box(point))
    });

    c.bench_function("curve25519/multiscalar_mul-base", |b| {
        let scalar1 = Scalar::random(&mut OsRng);
        let point1 = RISTRETTO_BASEPOINT_POINT;
        b.iter(|| Point::multiscalar_mul([black_box(scalar1)], [black_box(point1)]))
    });

    c.bench_function("curve25519/multiscalar_mul-variable", |b| {
        let scalar1 = Scalar::random(&mut OsRng);
        let point1 = Point::random(&mut OsRng);
        b.iter(|| Point::multiscalar_mul([black_box(scalar1)], [black_box(point1)]))
    });

    c.bench_function("curve25519/multiscalar_mul-base,variable", |b| {
        let scalar1 = Scalar::random(&mut OsRng);
        let point1 = RISTRETTO_BASEPOINT_POINT;
        let scalar2 = Scalar::random(&mut OsRng);
        let point2 = Point::random(&mut OsRng);
        b.iter(|| {
            Point::multiscalar_mul(
                [black_box(scalar1), black_box(scalar2)],
                [black_box(point1), black_box(point2)],
            )
        })
    });

    c.bench_function("curve25519/multiscalar_mul-variable,variable", |b| {
        let scalar1 = Scalar::random(&mut OsRng);
        let point1 = Point::random(&mut OsRng);
        let scalar2 = Scalar::random(&mut OsRng);
        let point2 = Point::random(&mut OsRng);
        b.iter(|| {
            Point::multiscalar_mul(
                [black_box(scalar1), black_box(scalar2)],
                [black_box(point1), black_box(point2)],
            )
        })
    });

    c.bench_function("curve25519/Scalar::from_bytes_mod_order_wide", |b| {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        b.iter(|| Scalar::from_bytes_mod_order_wide(black_box(&bytes)))
    });

    c.bench_function("curve25519/Point::from_uniform_bytes", |b| {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        b.iter(|| Point::from_uniform_bytes(black_box(&bytes)))
    });

    c.bench_function("curve25519/Point::compress", |b| {
        let point = Point::random(&mut OsRng);
        b.iter(|| black_box(&point).compress())
    });

    c.bench_function("curve25519/CompressedPoint::decompress", |b| {
        let point = Point::random(&mut OsRng);
        let compressed = point.compress();
        b.iter(|| black_box(&compressed).decompress())
    });

    c.bench_function("curve25519/Point::double_and_compress_batch-1", |b| {
        let point1 = Point::random(&mut OsRng);
        b.iter(|| Point::double_and_compress_batch(&[black_box(point1)]))
    });

    c.bench_function("curve25519/Point::double_and_compress_batch-2", |b| {
        let point1 = Point::random(&mut OsRng);
        let point2 = Point::random(&mut OsRng);
        b.iter(|| Point::double_and_compress_batch(&[black_box(point1), black_box(point2)]))
    });
}

fn voprf_bench(c: &mut Criterion) {
    c.bench_function("voprf/client start", |b| {
        let mut input = [0u8; 32];
        OsRng.fill_bytes(&mut input);
        let mut fast_rng = ChaCha12Rng::seed_from_u64(7);
        b.iter(|| voprf::start(black_box(&input), &mut fast_rng))
    });

    c.bench_function("voprf/OPRF evaluate", |b| {
        let mut input = [0u8; 32];
        OsRng.fill_bytes(&mut input);
        let (_blinding_factor, blinded_input) = voprf::start(&input, &mut OsRng);
        let private_key = voprf::PrivateKey::random(&mut OsRng);
        b.iter(|| voprf::blind_evaluate(black_box(&private_key), black_box(&blinded_input)))
    });

    c.bench_function("voprf/generate proof", |b| {
        let mut input = [0u8; 32];
        OsRng.fill_bytes(&mut input);
        let (_blinding_factor, blinded_input) = voprf::start(&input, &mut OsRng);
        let private_key = voprf::PrivateKey::random(&mut OsRng);
        let public_key = private_key.make_public_key();
        let blinded_output = voprf::blind_evaluate(&private_key, &blinded_input);
        let mut fast_rng = ChaCha12Rng::seed_from_u64(7);
        b.iter(|| {
            voprf::generate_proof(
                black_box(&private_key),
                black_box(&public_key),
                black_box(&blinded_input),
                black_box(&blinded_output),
                &mut fast_rng,
            )
        })
    });

    c.bench_function("voprf/VOPRF evaluate", |b| {
        let mut input = [0u8; 32];
        OsRng.fill_bytes(&mut input);
        let (_blinding_factor, blinded_input) = voprf::start(&input, &mut OsRng);
        let private_key = voprf::PrivateKey::random(&mut OsRng);
        let public_key = private_key.make_public_key();
        let mut fast_rng = ChaCha12Rng::seed_from_u64(7);
        b.iter(|| {
            voprf::blind_verifiable_evaluate(
                black_box(&private_key),
                black_box(&public_key),
                black_box(&blinded_input),
                &mut fast_rng,
            )
        })
    });

    c.bench_function("voprf/client finalize", |b| {
        let mut input = [0u8; 32];
        OsRng.fill_bytes(&mut input);
        let (blinding_factor, blinded_input) = voprf::start(&input, &mut OsRng);
        let private_key = voprf::PrivateKey::random(&mut OsRng);
        let blinded_output = voprf::blind_evaluate(&private_key, &blinded_input);
        b.iter(|| {
            voprf::finalize(
                black_box(&input),
                black_box(&blinding_factor),
                black_box(&blinded_output),
            )
        });
    });

    c.bench_function("voprf/client verify", |b| {
        let mut input = [0u8; 32];
        OsRng.fill_bytes(&mut input);
        let (_blinding_factor, blinded_input) = voprf::start(&input, &mut OsRng);
        let private_key = voprf::PrivateKey::random(&mut OsRng);
        let public_key = private_key.make_public_key();
        let (blinded_output, proof) =
            voprf::blind_verifiable_evaluate(&private_key, &public_key, &blinded_input, &mut OsRng);
        b.iter(|| {
            voprf::verify_proof(
                black_box(&blinded_input),
                black_box(&blinded_output),
                black_box(&public_key),
                black_box(&proof),
            )
        });
    });

    c.bench_function("voprf/OPRF total", |b| {
        let mut input = [0u8; 32];
        OsRng.fill_bytes(&mut input);
        let private_key = voprf::PrivateKey::random(&mut OsRng);
        let mut fast_rng = ChaCha12Rng::seed_from_u64(7);
        b.iter(|| {
            // Client
            let (blinding_factor, blinded_input) = voprf::start(black_box(&input), &mut fast_rng);
            let request = marshalling::to_vec(&blinded_input).unwrap();

            // Server
            let response = {
                let blinded_input: voprf::BlindedInput = marshalling::from_slice(&request).unwrap();
                let blinded_output = voprf::blind_evaluate(black_box(&private_key), &blinded_input);
                marshalling::to_vec(&blinded_output).unwrap()
            };

            // Client
            let blinded_output: voprf::BlindedOutput = marshalling::from_slice(&response).unwrap();
            voprf::finalize(black_box(&input), &blinding_factor, &blinded_output)
        });
    });

    c.bench_function("voprf/VOPRF total", |b| {
        let mut input = [0u8; 32];
        OsRng.fill_bytes(&mut input);
        let private_key = voprf::PrivateKey::random(&mut OsRng);
        let public_key = private_key.make_public_key();
        let mut fast_rng = ChaCha12Rng::seed_from_u64(7);
        b.iter(|| {
            // Client
            let (blinding_factor, blinded_input) = voprf::start(black_box(&input), &mut fast_rng);
            let request = marshalling::to_vec(&blinded_input).unwrap();

            // Server
            #[derive(Deserialize, Serialize)]
            struct Response {
                blinded_output: voprf::BlindedOutput,
                proof: voprf::Proof,
            }
            let response = {
                let blinded_input: voprf::BlindedInput = marshalling::from_slice(&request).unwrap();
                let (blinded_output, proof) = voprf::blind_verifiable_evaluate(
                    black_box(&private_key),
                    black_box(&public_key),
                    &blinded_input,
                    &mut fast_rng,
                );
                marshalling::to_vec(&Response {
                    blinded_output,
                    proof,
                })
                .unwrap()
            };

            // Client
            let Response {
                blinded_output,
                proof,
            } = marshalling::from_slice(&response).unwrap();
            voprf::verify_proof(&blinded_input, &blinded_output, &public_key, &proof).unwrap();
            voprf::finalize(black_box(&input), &blinding_factor, &blinded_output)
        });
    });

    c.bench_function("voprf/unoblivious evaluate", |b| {
        let mut input = [0u8; 32];
        OsRng.fill_bytes(&mut input);
        let private_key = voprf::PrivateKey::random(&mut OsRng);
        b.iter(|| voprf::unoblivious_evaluate(black_box(&private_key), black_box(&input)));
    });
}

criterion_group!(benches, sha512_bench, curve25519_bench, voprf_bench);
criterion_main!(benches);
