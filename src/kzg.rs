use ark_ec::ProjectiveCurve;
use ark_ec::{msm::VariableBaseMSM, PairingEngine};
use ark_ff::PrimeField;
use ark_poly::UVPolynomial;
use ark_poly_commit::kzg10::{Powers, Proof, Randomness, UniversalParams, VerifierKey, KZG10};
use ark_std::{end_timer, start_timer};
#[cfg(feature = "parallel")]
use rayon::iter::IntoParallelRefIterator;
#[cfg(feature = "parallel")]
use rayon::iter::ParallelIterator;
use std::ops::Div;

/// Specializes the public parameters for a given maximum degree `d` for polynomials
/// `d` should be less that `pp.max_degree()`.
pub fn trim<E>(pp: &UniversalParams<E>, mut supported_degree: usize) -> (Powers<E>, VerifierKey<E>)
where
    E: PairingEngine,
{
    if supported_degree == 1 {
        supported_degree += 1;
    }
    let powers_of_g = pp.powers_of_g[..=supported_degree].to_vec();
    let powers_of_gamma_g = (0..=supported_degree)
        .map(|i| pp.powers_of_gamma_g[&i])
        .collect();

    let powers = Powers {
        powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
        powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
    };
    let vk = VerifierKey {
        g: pp.powers_of_g[0],
        gamma_g: pp.powers_of_gamma_g[&0],
        h: pp.h,
        beta_h: pp.beta_h,
        prepared_h: pp.prepared_h.clone(),
        prepared_beta_h: pp.prepared_beta_h.clone(),
    };
    (powers, vk)
}

pub(crate) fn check_degree_is_too_large(degree: usize, num_powers: usize) -> bool {
    let num_coefficients = degree + 1;
    num_coefficients <= num_powers
}

fn open_with_witness_polynomial<E, P>(
    powers: &Powers<E>,
    point: P::Point,
    randomness: &Randomness<E::Fr, P>,
    witness_polynomial: &P,
    hiding_witness_polynomial: Option<&P>,
) -> Proof<E>
where
    E: PairingEngine,
    P: UVPolynomial<E::Fr, Point = E::Fr>,
    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
    assert!(
        check_degree_is_too_large(witness_polynomial.degree(), powers.size()),
        "degree is too large"
    );
    let (num_leading_zeros, witness_coeffs) =
        skip_leading_zeros_and_convert_to_bigints(witness_polynomial);

    let witness_comm_time = start_timer!(|| "Computing commitment to witness polynomial");
    let mut w = VariableBaseMSM::multi_scalar_mul(
        &powers.powers_of_g[num_leading_zeros..],
        &witness_coeffs,
    );
    end_timer!(witness_comm_time);

    let random_v = if let Some(hiding_witness_polynomial) = hiding_witness_polynomial {
        let blinding_p = &randomness.blinding_polynomial;
        let blinding_eval_time = start_timer!(|| "Evaluating random polynomial");
        let blinding_evaluation = blinding_p.evaluate(&point);
        end_timer!(blinding_eval_time);

        let random_witness_coeffs = convert_to_bigints(&hiding_witness_polynomial.coeffs());
        let witness_comm_time =
            start_timer!(|| "Computing commitment to random witness polynomial");
        w += &VariableBaseMSM::multi_scalar_mul(&powers.powers_of_gamma_g, &random_witness_coeffs);
        end_timer!(witness_comm_time);
        Some(blinding_evaluation)
    } else {
        None
    };

    Proof {
        w: w.into_affine(),
        random_v,
    }
}

/// On input a polynomial `p` and a point `point`, outputs a proof for the same.
pub fn open<E, P>(
    powers: &Powers<E>,
    p: &P,
    point: P::Point,
    rand: &Randomness<E::Fr, P>,
) -> Proof<E>
where
    E: PairingEngine,
    P: UVPolynomial<E::Fr, Point = E::Fr>,
    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
    assert!(
        check_degree_is_too_large(p.degree(), powers.size()),
        "degree is too large"
    );

    let open_time = start_timer!(|| format!("Opening polynomial of degree {}", p.degree()));

    let witness_time = start_timer!(|| "Computing witness polynomials");
    let (witness_poly, hiding_witness_poly) =
        KZG10::<E, P>::compute_witness_polynomial(p, point, rand).unwrap();
    end_timer!(witness_time);

    let proof = open_with_witness_polynomial(
        powers,
        point,
        rand,
        &witness_poly,
        hiding_witness_poly.as_ref(),
    );

    end_timer!(open_time);
    proof
}

fn skip_leading_zeros_and_convert_to_bigints<F: PrimeField, P: UVPolynomial<F>>(
    p: &P,
) -> (usize, Vec<F::BigInt>) {
    let mut num_leading_zeros = 0;
    while num_leading_zeros < p.coeffs().len() && p.coeffs()[num_leading_zeros].is_zero() {
        num_leading_zeros += 1;
    }
    let coeffs = convert_to_bigints(&p.coeffs()[num_leading_zeros..]);
    (num_leading_zeros, coeffs)
}

fn convert_to_bigints<F: PrimeField>(p: &[F]) -> Vec<F::BigInt> {
    let to_bigint_time = start_timer!(|| "Converting polynomial coeffs to bigints");
    let coeffs = ark_std::cfg_iter!(p)
        .map(|s| s.into_repr())
        .collect::<Vec<_>>();
    end_timer!(to_bigint_time);
    coeffs
}
