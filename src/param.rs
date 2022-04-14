use ark_ec::AffineCurve;
use ark_ec::PairingEngine;
use ark_ec::ProjectiveCurve;
use ark_std::rand::Rng;
use ark_std::One;
use ark_std::UniformRand;
use ark_std::Zero;

#[cfg(feature = "parallel")]
use rayon::iter::IntoParallelRefIterator;
#[cfg(feature = "parallel")]
use rayon::iter::ParallelIterator;

/// A StructuredReferenceString contains three four components:
/// - g = \[ G, alpha * G,       alpha^2 G,      \dots,   alpha^{n-1} G,
///           _, alpha^{n+1} * G, alpha^^{n+2} G, \dots,   alpha^{2n-1} G \]
/// - h = \[ H, alpha * H,       alpha^2 H,      \dots,   alpha^{n-1} H \]
/// - t = e(alpha^n * G, H)
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StructuredReferenceString<E: PairingEngine, const N: usize> {
    g: Vec<E::G1Affine>,
    h: Vec<E::G2Affine>,
    t: E::Fqk,
}

impl<E: PairingEngine, const N: usize> StructuredReferenceString<E, N> {
    pub fn new_srs_for_testing<R: Rng>(rng: &mut R) -> Self {
        // compute the alpha base as 1, alpha, alpha^2... alpha^{2n-1}
        // with alpha^n empty
        let alpha = E::Fr::rand(rng);
        let mut alpha_base = Vec::<E::Fr>::with_capacity(N << 1);
        alpha_base.push(E::Fr::one());
        alpha_base.push(alpha);
        for _ in 1..N << 1 {
            alpha_base.push(alpha * alpha_base.last().unwrap())
        }
        alpha_base[N] = E::Fr::zero();

        #[cfg(not(feature = "parallel"))]
        let (g, h) = {
            // - g = \[ G, alpha * G,       alpha^2 G,      \dots,   alpha^{n-1} G,
            //          _, alpha^{n+1} * G, alpha^^{n+2} G, \dots,   alpha^{2n-1} G \]
            let g: Vec<E::G1Projective> = alpha_base
                .iter()
                .map(|&alpha_power| E::G1Affine::prime_subgroup_generator().mul(alpha_power))
                .collect();

            // - h = \[ H, alpha * H,       alpha^2 H,      \dots,   alpha^{n-1} H \]
            let h: Vec<E::G2Projective> = alpha_base
                .iter()
                .take(N)
                .map(|&alpha_power| E::G2Affine::prime_subgroup_generator().mul(alpha_power))
                .collect();
            (g, h)
        };

        #[cfg(feature = "parallel")]
        let (g, h) = {
            // - g = \[ G, alpha * G,       alpha^2 G,      \dots,   alpha^{n-1} G,
            //          _, alpha^{n+1} * G, alpha^^{n+2} G, \dots,   alpha^{2n-1} G \]
            let g: Vec<E::G1Projective> = alpha_base
                .par_iter()
                .map(|&alpha_power| E::G1Affine::prime_subgroup_generator().mul(alpha_power))
                .collect();

            // - h = \[ H, alpha * H,       alpha^2 H,      \dots,   alpha^{n-1} H \]
            let h: Vec<E::G2Projective> = alpha_base[0..N]
                .par_iter()
                .map(|&alpha_power| E::G2Affine::prime_subgroup_generator().mul(alpha_power))
                .collect();

            (g, h)
        };

        let g = E::G1Projective::batch_normalization_into_affine(&g);
        let h = E::G2Projective::batch_normalization_into_affine(&h);

        // - t  = e(alpha^n * G, H)
        let t = E::pairing(
            E::G1Affine::prime_subgroup_generator().mul(alpha_base[N]),
            E::G2Affine::prime_subgroup_generator(),
        );

        Self { g, h, t }
    }
}
