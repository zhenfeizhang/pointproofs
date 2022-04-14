use crate::param::ProverParam;
use crate::param::VerifierParam;
use crate::Commitment;
use crate::CommitmentScheme;
use ark_ec::msm::VariableBaseMSM;
use ark_ec::AffineCurve;
use ark_ec::PairingEngine;
use ark_ec::ProjectiveCurve;
use ark_ff::Field;
use ark_ff::PrimeField;
use std::ops::Neg;

impl<E: PairingEngine, const N: usize> CommitmentScheme for Commitment<E, N> {
    type ProverParam = ProverParam<E, N>;
    type VerifierParam = VerifierParam<E, N>;
    type MessageUnit = E::Fr;
    type Commitment = Self;
    type Witness = E::G1Projective;

    /// Commit to a list of inputs with prover parameters
    fn commit(pp: &Self::ProverParam, inputs: &[Self::MessageUnit]) -> Self {
        assert!(inputs.len() <= N);

        let scalars: Vec<<E::Fr as PrimeField>::BigInt> =
            inputs.iter().map(|x| x.into_repr()).collect();
        Self {
            commitment: VariableBaseMSM::multi_scalar_mul(&pp.g[0..inputs.len()], scalars.as_ref()),
        }
    }

    /// Open an input at a given position
    fn open(pp: &Self::ProverParam, inputs: &[Self::MessageUnit], pos: usize) -> Self::Witness {
        assert!(inputs.len() <= N);

        let scalars: Vec<<E::Fr as PrimeField>::BigInt> =
            inputs.iter().map(|x| x.into_repr()).collect();
        VariableBaseMSM::multi_scalar_mul(
            pp.g[N - pos..N - pos + inputs.len()].as_ref(),
            scalars.as_ref(),
        )
    }

    /// Verify the input/witness pair is correct
    fn verify(
        &self,
        vp: &Self::VerifierParam,
        input: &Self::MessageUnit,
        pos: usize,
        witness: &Self::Witness,
    ) -> bool {
        let input_inverse = input.inverse().unwrap();

        let com = self
            .commitment
            .mul(&input_inverse.into_repr())
            .into_affine();
        let proof = witness.mul(input_inverse.neg().into_repr()).into_affine();
        let pairing_prod_inputs = vec![
            (com.into(), vp.h[N - pos - 1].into()),
            (proof.into(), E::G2Affine::prime_subgroup_generator().into()),
        ];
        E::product_of_pairings(pairing_prod_inputs.iter()) == vp.t
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::StructuredReferenceString;
    use ark_bn254::Bn254;
    use ark_std::rand::RngCore;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    const NUM_TEST: usize = 10;

    macro_rules! test_single_commit_opening {
        ($engine: tt, $dim: expr, $disc: tt) => {
            let mut rng = test_rng();

            let srs = StructuredReferenceString::<$engine, $dim>::new_srs_for_testing(&mut rng);
            let prover_param: ProverParam<$engine, $dim> = (&srs).into();
            let verifier_param: VerifierParam<$engine, $dim> = (&srs).into();

            let message: Vec<<$engine as PairingEngine>::Fr> = (0..$dim)
                .map(|_| <$engine as PairingEngine>::Fr::rand(&mut rng))
                .collect();
            let commitment = Commitment::<$engine, $dim>::commit(&prover_param, &message);
            for _ in (0..NUM_TEST) {
                let pos = (rng.next_u32() % $dim) as usize;
                let witness = Commitment::<$engine, $dim>::open(&prover_param, &message, pos);
                assert!(commitment.verify(&verifier_param, &message[pos], pos, &witness))
            }
        };
    }

    #[test]
    fn test_single_commit_opening() {
        test_single_commit_opening!(Bn254, 128, "bn254");
    }
}
