use curv::arithmetic::Converter;
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use curv::BigInt;
use sha2::Digest;

pub struct DLogProof {
    // Proof values
    pub commitment: Point<Secp256k1>,
    pub response: Scalar<Secp256k1>,
}

impl DLogProof {
    fn new(commitment: Point<Secp256k1>, response: Scalar<Secp256k1>) -> Self {
        DLogProof { commitment, response }
    }

    fn compute_challenge(
        session_id: &str, 
        participant_id: i32, 
        points: Vec<Point<Secp256k1>>
    ) -> Scalar<Secp256k1> {
        let mut sha_hash = sha2::Sha256::new();
        sha_hash.update(session_id.as_bytes());
        sha_hash.update(&participant_id.to_be_bytes());
        for point in points {
            sha_hash.update(point.to_bytes(false).as_ref());
        }
        let sha_hash_result = sha_hash.finalize();
        let sha_hash_bytes: &[u8] = &sha_hash_result[..];

        let hash_as_bigint = BigInt::from_bytes(sha_hash_bytes.try_into().unwrap());
        let challenge = Scalar::<Secp256k1>::from_bigint(&hash_as_bigint);

        if challenge.is_zero() {
            panic!("Hash resulted in zero scalar");
        } else {
            challenge
        }
    }

    pub fn generate_proof(
        session_id: &str,
        participant_id: i32,
        private_key: Scalar<Secp256k1>,
        public_key: Point<Secp256k1>,
        base_point: Point<Secp256k1>,
    ) -> DLogProof {
        let random_scalar = Scalar::random();
        let commitment = base_point.clone() * random_scalar.clone();
        let challenge = DLogProof::compute_challenge(
            session_id, 
            participant_id, 
            vec![base_point.clone(), public_key.clone(), commitment.clone()]
        );

        let response = random_scalar + private_key * challenge;

        DLogProof::new(commitment, response)
    }

    pub fn verify_proof(
        &self,
        session_id: &str,
        participant_id: i32,
        public_key: Point<Secp256k1>,
        base_point: Point<Secp256k1>,
    ) -> bool {
        let challenge = DLogProof::compute_challenge(
            session_id,
            participant_id,
            vec![base_point.clone(), public_key.clone(), self.commitment.clone()],
        );
        let lhs = base_point * self.response.clone();
        let rhs = self.commitment.clone() + challenge * public_key;

        lhs == rhs
    }
}

//tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_proof() {
        let session_id = "session_1";
        let participant_id = 1;

        let base_point = Point::generator();
        let private_key = Scalar::random();
        let public_key = base_point.clone() * private_key.clone();

        let dlog_proof = DLogProof::generate_proof(
            session_id, 
            participant_id, 
            private_key, 
            public_key.clone(), 
            base_point.into()
        );
        assert!(dlog_proof.verify_proof(session_id, participant_id, public_key, base_point.into()));
    }

    #[test]
    fn test_generate_proof_fail() {
        let session_id = "session_1";
        let participant_id = 1;

        let base_point = Point::generator();
        let private_key = Scalar::random();
        let public_key = base_point.clone() * private_key.clone();

        let dlog_proof = DLogProof::generate_proof(
            session_id, 
            participant_id, 
            private_key, 
            public_key.clone(), 
            base_point.into()
        );
        assert!(!dlog_proof.verify_proof(
            session_id, 
            participant_id, 
            public_key.clone() + base_point, 
            base_point.into()
        ));
    }

    #[test]
    fn test_generate_proof_fail2() {
        let session_id = "session_1";
        let participant_id = 1;

        let base_point = Point::generator();
        let private_key = Scalar::random();
        let public_key = base_point.clone() * private_key.clone();

        let dlog_proof = DLogProof::generate_proof(
            session_id, 
            participant_id, 
            private_key, 
            public_key.clone(), 
            base_point.into()
        );
        assert!(!dlog_proof.verify_proof(
            session_id,
            participant_id,
            public_key.clone() + base_point.clone() * Scalar::random(),
            base_point.into()
        ));
    }
}
