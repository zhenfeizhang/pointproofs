#![allow(dead_code)]

#[macro_use]
extern crate criterion;

use std::ops::Div;

use ark_bls12_377::Bls12_377;
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::PairingEngine;
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use ark_poly_commit::kzg10::KZG10;
use ark_std::rand::RngCore;
use ark_std::rand::SeedableRng;
use ark_std::test_rng;
use ark_std::UniformRand;
use criterion::Criterion;
use pointproof::Commitment;
use pointproof::CommitmentScheme;
use pointproof::ProverParam;
use pointproof::StructuredReferenceString;
use pointproof::VerifierParam;
use pointproof::{open, trim};
use rand_chacha::ChaCha20Rng;

criterion_main!(bench);
criterion_group!(bench, toe_to_toe);

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

    // param_gen_bench!(Bn254, 128, bench_group, "bn254");
    // param_gen_bench!(Bn254, 1024, bench_group, "bn254");
    // param_gen_bench!(Bn254, 65535, bench_group, "bn254");

    param_gen_bench!(Bls12_381, 128, bench_group, "bls12-381");
    param_gen_bench!(Bls12_381, 1024, bench_group, "bls12-381");
    param_gen_bench!(Bls12_381, 65535, bench_group, "bls12-381");

    // param_gen_bench!(Bls12_377, 128, bench_group, "bls12-377");
    // param_gen_bench!(Bls12_377, 1024, bench_group, "bls12-377");
    // param_gen_bench!(Bls12_377, 65535, bench_group, "bls12-377");
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

    // single_commit_and_open_bench!(Bn254, 128, bench_group, "bn254");
    // single_commit_and_open_bench!(Bn254, 1024, bench_group, "bn254");
    // single_commit_and_open_bench!(Bn254, 65535, bench_group, "bn254");

    single_commit_and_open_bench!(Bls12_381, 128, bench_group, "bls12-381");
    single_commit_and_open_bench!(Bls12_381, 1024, bench_group, "bls12-381");
    single_commit_and_open_bench!(Bls12_381, 65535, bench_group, "bls12-381");

    // single_commit_and_open_bench!(Bls12_377, 128, bench_group, "bls12-377");
    // single_commit_and_open_bench!(Bls12_377, 1024, bench_group, "bls12-377");
    // single_commit_and_open_bench!(Bls12_377, 65535, bench_group, "bls12-377");
}

fn bench_kzg(c: &mut Criterion) {
    bench_kzg_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>>(c, 128);
    bench_kzg_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>>(c, 1024);
    bench_kzg_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>>(c, 65535);
}

fn bench_kzg_helper<E, P>(c: &mut Criterion, dim: usize)
where
    E: PairingEngine,
    P: UVPolynomial<E::Fr, Point = E::Fr> + Clone,
    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
    let mut rng = test_rng();
    let degree = dim;
    let mut bench_group = c.benchmark_group(format!("kzg dim {}", degree));

    let bench_str = format!("setup");
    bench_group.bench_function(bench_str, move |b| {
        b.iter(|| {
            let _ = KZG10::<E, P>::setup(degree, false, &mut rng).unwrap();
        })
    });

    let mut rng = test_rng();
    let pp = KZG10::<E, P>::setup(degree, false, &mut rng).unwrap();
    let (ck, vk) = trim(&pp, degree);
    let p = P::rand(degree, &mut rng);
    let point = E::Fr::rand(&mut rng);

    let bench_str = format!("commit");
    let ck_clone = ck.clone();
    let p_clone = p.clone();
    bench_group.bench_function(bench_str, move |b| {
        b.iter(|| {
            let _ = KZG10::<E, P>::commit(&ck_clone, &p_clone, None, None).unwrap();
        })
    });

    let p_clone = p.clone();
    let (comm, rand) = KZG10::<E, P>::commit(&ck, &p_clone, None, None).unwrap();

    let bench_str = format!("evaluate");
    bench_group.bench_function(bench_str, move |b| {
        b.iter(|| {
            let _ = p_clone.evaluate(&point);
        })
    });

    let p_clone = p.clone();
    let value = p.evaluate(&point);
    let proof = open(&ck, &p_clone, point, &rand);

    let bench_str = format!("prove");
    let p_clone = p.clone();
    bench_group.bench_function(bench_str, move |b| {
        b.iter(|| {
            let _ = open(&ck, &p_clone, point, &rand);
        })
    });

    let bench_str = format!("verify");
    bench_group.bench_function(bench_str, move |b| {
        b.iter(|| {
            assert!(
                KZG10::<E, P>::check(&vk, &comm, point, value, &proof).unwrap(),
                "proof was incorrect for max_degree = {}, polynomial_degree = {}",
                degree,
                p.degree(),
            )
        })
    });
}

fn toe_to_toe(c: &mut Criterion) {
    toe_to_toe_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>, 4>(c);
    toe_to_toe_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>, 16>(c);
    toe_to_toe_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>, 64>(c);
    toe_to_toe_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>, 256>(c);
    toe_to_toe_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>, 1024>(c);
    toe_to_toe_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>, 4096>(c);
    toe_to_toe_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>, 16384>(c);
    toe_to_toe_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>, 65536>(c);
    toe_to_toe_helper::<Bls12_381, DensePolynomial<<Bls12_381 as PairingEngine>::Fr>, 262144>(c);
}

fn toe_to_toe_helper<E, P, const M: usize>(c: &mut Criterion)
where
    E: PairingEngine,
    P: UVPolynomial<E::Fr, Point = E::Fr> + Clone,
    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
    let dim = M;
    let mut ttt = c.benchmark_group(format!("ttt {}", dim));

    // =================
    // setup
    // =================
    let mut rng = test_rng();
    let bench_str = "kzg_setup";
    ttt.bench_function(bench_str, move |b| {
        b.iter(|| {
            let _ = KZG10::<E, P>::setup(dim, false, &mut rng).unwrap();
        })
    });
    let mut rng = test_rng();
    let bench_str = "pps_setup";
    ttt.bench_function(bench_str, move |b| {
        b.iter(|| {
            let _ = StructuredReferenceString::<E, M>::new_srs_for_testing(&mut rng);
        });
    });

    // =================
    // commit
    // =================
    let mut rng = test_rng();
    let kzg_pp = KZG10::<E, P>::setup(dim, false, &mut rng).unwrap();
    let (ck, vk) = trim(&kzg_pp, dim);
    let p = P::rand(dim, &mut rng);
    let point = E::Fr::rand(&mut rng);

    let bench_str = "kzg_commit";
    let ck_clone = ck.clone();
    let p_clone = p.clone();
    ttt.bench_function(bench_str, move |b| {
        b.iter(|| {
            let _ = KZG10::<E, P>::commit(&ck_clone, &p_clone, None, None).unwrap();
        })
    });
    let srs = StructuredReferenceString::<E, M>::new_srs_for_testing(&mut rng);
    let prover_param: ProverParam<E, M> = (&srs).into();
    let verifier_param: VerifierParam<E, M> = (&srs).into();
    let message: Vec<<E as PairingEngine>::Fr> = (0..M)
        .map(|_| <E as PairingEngine>::Fr::rand(&mut rng))
        .collect();

    let (comm, rand) = KZG10::<E, P>::commit(&ck, &p, None, None).unwrap();
    

    let commitment = Commitment::<E, M>::commit(&prover_param, &message);
    let prover_param_clone = prover_param.clone();
    let message_clone = message.clone();
    let bench_str = "pps_commit";
    ttt.bench_function(bench_str, move |b| {
        b.iter(|| {
            let _ = Commitment::<E, M>::commit(&prover_param_clone, &message_clone);
        });
    });

    
    // =================
    // open
    // =================
    let bench_str = format!("kzg_prove");
    let p_clone = p.clone();
    let ck_clone = ck.clone();
    let rand_clone = rand.clone();
    ttt.bench_function(bench_str, move |b| {
        b.iter(|| {
            let _ = open(&ck_clone, &p_clone, point, &rand_clone);
        })
    });

    let value = p.evaluate(&point);
    let proof = open(&ck, &p, point, &rand);


    let pos = (rng.next_u32() % dim as u32) as usize;
    let m = message[pos];
    let witness = Commitment::<E, M>::open(&prover_param, &message, pos);

    let bench_str = "pps_prove";
    ttt.bench_function(bench_str, move |b| {
        b.iter(|| {
            let pos = (rng.next_u32() % dim as u32) as usize;
            let _ = Commitment::<E, M>::open(&prover_param, &message, pos);
        });
    });

    // =================
    // verify
    // =================
    let bench_str = format!("kzg_verify");
    ttt.bench_function(bench_str, move |b| {
        b.iter(|| {
            assert!(
                KZG10::<E, P>::check(&vk, &comm, point, value, &proof).unwrap(),
                "proof was incorrect for max_degree = {}, polynomial_degree = {}",
                dim,
                p.degree(),
            )
        })
    });

    let bench_str = "pps_verify";
    ttt.bench_function(bench_str, move |b| {
        b.iter(|| assert!(commitment.verify(&verifier_param, &m, pos, &witness)));
    });

}
