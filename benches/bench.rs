#[macro_use]
extern crate criterion;

use ark_bls12_377::Bls12_377;
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::PairingEngine;
use ark_std::rand::RngCore;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use criterion::Criterion;
use pointproof::Commitment;
use pointproof::CommitmentScheme;
use pointproof::ProverParam;
use pointproof::StructuredReferenceString;
use pointproof::VerifierParam;
use rand_chacha::ChaCha20Rng;

criterion_main!(bench);
criterion_group!(bench, single_commit_and_open, param_gen,);

macro_rules! param_gen_bench {
    ($engine: tt, $dim: expr, $bencher: tt, $disc: tt) => {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let bench_str = format!("curve: {}, dimension: {}", $disc, $dim,);
        $bencher.bench_function(bench_str, move |b| {
            b.iter(|| {
                let _ = StructuredReferenceString::<$engine, $dim>::new_srs_for_testing(&mut rng);
            });
        });
    };
}

fn param_gen(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("SRS generation");
    bench_group.sample_size(10);

    param_gen_bench!(Bn254, 128, bench_group, "bn254");
    param_gen_bench!(Bn254, 1024, bench_group, "bn254");
    param_gen_bench!(Bn254, 65535, bench_group, "bn254");

    param_gen_bench!(Bls12_381, 128, bench_group, "bls12-381");
    param_gen_bench!(Bls12_381, 1024, bench_group, "bls12-381");
    param_gen_bench!(Bls12_381, 65535, bench_group, "bls12-381");

    param_gen_bench!(Bls12_377, 128, bench_group, "bls12-377");
    param_gen_bench!(Bls12_377, 1024, bench_group, "bls12-377");
    param_gen_bench!(Bls12_377, 65535, bench_group, "bls12-377");
}

macro_rules! single_commit_and_open_bench {
    ($engine: tt, $dim: expr, $bencher: tt, $disc: tt) => {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let srs = StructuredReferenceString::<$engine, $dim>::new_srs_for_testing(&mut rng);
        let prover_param: ProverParam<$engine, $dim> = (&srs).into();
        let verifier_param: VerifierParam<$engine, $dim> = (&srs).into();
        let message: Vec<<$engine as PairingEngine>::Fr> = (0..$dim)
            .map(|_| <$engine as PairingEngine>::Fr::rand(&mut rng))
            .collect();

        let commitment = Commitment::<$engine, $dim>::commit(&prover_param, &message);
        let prover_param_clone = prover_param.clone();
        let message_clone = message.clone();
        let bench_str = format!("curve {}, commit to {} messages", $disc, $dim,);
        $bencher.bench_function(bench_str, move |b| {
            b.iter(|| {
                let _ = Commitment::<$engine, $dim>::commit(&prover_param_clone, &message_clone);
            });
        });

        let pos = (rng.next_u32() % $dim) as usize;
        let m = message[pos];
        let witness = Commitment::<$engine, $dim>::open(&prover_param, &message, pos);

        let bench_str = format!("curve {}, dim {}, open 1 message", $disc, $dim,);
        $bencher.bench_function(bench_str, move |b| {
            b.iter(|| {
                let pos = (rng.next_u32() % $dim) as usize;
                let _ = Commitment::<$engine, $dim>::open(&prover_param, &message, pos);
            });
        });

        let bench_str = format!("curve {}, dim {}, verify 1 message", $disc, $dim,);
        $bencher.bench_function(bench_str, move |b| {
            b.iter(|| assert!(commitment.verify(&verifier_param, &m, pos, &witness)));
        });
    };
}

fn single_commit_and_open(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("Single proof");
    bench_group.sample_size(10);

    single_commit_and_open_bench!(Bn254, 128, bench_group, "bn254");
    single_commit_and_open_bench!(Bn254, 1024, bench_group, "bn254");
    single_commit_and_open_bench!(Bn254, 65535, bench_group, "bn254");

    single_commit_and_open_bench!(Bls12_381, 128, bench_group, "bls12-381");
    single_commit_and_open_bench!(Bls12_381, 1024, bench_group, "bls12-381");
    single_commit_and_open_bench!(Bls12_381, 65535, bench_group, "bls12-381");

    single_commit_and_open_bench!(Bls12_377, 128, bench_group, "bls12-377");
    single_commit_and_open_bench!(Bls12_377, 1024, bench_group, "bls12-377");
    single_commit_and_open_bench!(Bls12_377, 65535, bench_group, "bls12-377");
}
