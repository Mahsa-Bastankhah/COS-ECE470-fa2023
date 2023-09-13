use serde::{Serialize,Deserialize};
use ring::signature::{Ed25519KeyPair, Signature};
use rand::Rng;
use crate::types::key_pair;
use ring::signature::KeyPair;
use super::address::Address;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Transaction {
    pub sender: Address,
    pub receiver: Address,
    pub value: i32,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Create digital signature of a transaction
pub fn sign(t: &Transaction, key: &Ed25519KeyPair) -> Signature {
    // Serialize the transaction
    let serialized_data = bincode::serialize(t).expect("Serialization failed");

    // Sign the serialized data using the private key
    let signature = key.sign(&serialized_data);

    // Convert the public key to a vector of bytes
    let public_key_bytes = key.public_key().as_ref().to_vec();

    SignedTransaction {
        transaction: t.clone(),
        signature: signature.as_ref().to_vec(),
        public_key: public_key_bytes,
    };

    signature
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &Transaction, public_key: &[u8], signature: &[u8]) -> bool {
    // Serialize the transaction
    let serialized_data = bincode::serialize(t).expect("Serialization failed");

    // Create an Ed25519 key pair from the public key
    let public_key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key);

    // Verify the signature using the public key
    public_key.verify(serialized_data.as_ref(), signature).is_ok()
}

#[cfg(any(test, test_utilities))]
pub fn generate_random_transaction() -> Transaction {

    let mut sender_key = key_pair::random();
    let mut public_key_bytes = sender_key.public_key().as_ref();
    let sender = Address::from_public_key_bytes(public_key_bytes);

    let mut receiver_key = key_pair::random();
    public_key_bytes = receiver_key.public_key().as_ref();
    let receiver = Address::from_public_key_bytes(public_key_bytes);

    let mut rng = rand::thread_rng();
    let value = rng.gen();

    Transaction { sender, receiver, value }
}

// DO NOT CHANGE THIS COMMENT, IT IS FOR AUTOGRADER. BEFORE TEST

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::key_pair;
    use ring::signature::KeyPair;


    #[test]
    fn sign_verify() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify(&t, key.public_key().as_ref(), signature.as_ref()));
    }
    #[test]
    fn sign_verify_two() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        let key_2 = key_pair::random();
        let t_2 = generate_random_transaction();
        assert!(!verify(&t_2, key.public_key().as_ref(), signature.as_ref()));
        assert!(!verify(&t, key_2.public_key().as_ref(), signature.as_ref()));
    }
}

// DO NOT CHANGE THIS COMMENT, IT IS FOR AUTOGRADER. AFTER TEST