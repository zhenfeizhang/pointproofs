#[macro_use]
extern crate criterion;

use ark_bls12_377::Bls12_377;
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_std::rand::SeedableRng;
use criterion::Criterion;
use pointproof::StructuredReferenceString;
use rand_chacha::ChaCha20Rng;

criterion_main!(bench);
criterion_group!(bench, param_gen,);

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
