use std::fmt::Display;

use plonky2::{hash::hash_types::{RichField, HashOut}};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::{sha256::WitnessHashSha2, sha256_merkle::{MerkleProofSha256Gadget, DeltaMerkleProofSha256Gadget}, WitnessHash, sha256_truncated_merkle::{MerkleProofTruncatedSha256Gadget, DeltaMerkleProofTruncatedSha256Gadget}};

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy)]
pub struct Hash256(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 32]);

impl Hash256 {
    pub fn from_str(s: &str) -> Result<Self, ()> {
        let bytes = hex::decode(s).unwrap();
        assert_eq!(bytes.len(), 32);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}


impl Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}
#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy)]
pub struct Hash192(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 24]);

impl Hash192 {
    pub fn from_str(s: &str) -> Result<Self, ()> {
        let bytes = hex::decode(s).unwrap();
        assert_eq!(bytes.len(), 24);
        let mut array = [0u8; 24];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

impl Display for Hash192 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}
fn read_u48_in_field_from_bytes<F:RichField>(bytes: &[u8; 24], index: usize) -> F {
    // leave as non-canonical incase of field with a prime <= 48 bits
    F::from_noncanonical_u64((bytes[index] as u64) << 40
        | (bytes[index+1] as u64) << 32
        | (bytes[index+2] as u64) << 24
        | (bytes[index+3] as u64) << 16
        | (bytes[index+4] as u64) << 8
        | (bytes[index+5] as u64))
}
impl<F:RichField> From<&Hash192> for HashOut<F> {
    fn from(bytes: &Hash192) -> Self {
        HashOut { elements: [
            read_u48_in_field_from_bytes(&bytes.0, 0),
            read_u48_in_field_from_bytes(&bytes.0, 6),
            read_u48_in_field_from_bytes(&bytes.0, 12),
            read_u48_in_field_from_bytes(&bytes.0, 18),
        ] }
    }
}

impl Hash192 {
    pub fn to_hash_out<F:RichField>(&self) -> HashOut<F> {
        HashOut { elements: [
            read_u48_in_field_from_bytes(&self.0, 0),
            read_u48_in_field_from_bytes(&self.0, 6),
            read_u48_in_field_from_bytes(&self.0, 12),
            read_u48_in_field_from_bytes(&self.0, 18),
        ] }
    }
    pub fn from_hash_out<F:RichField>(hash: HashOut<F>)->Self {
        let mut bytes = [0u8; 24];
        for i in 0..4 {
            let element = hash.elements[i].to_canonical_u64();
            bytes[i*6] = (element >> 40) as u8;
            bytes[i*6+1] = (element >> 32) as u8;
            bytes[i*6+2] = (element >> 24) as u8;
            bytes[i*6+3] = (element >> 16) as u8;
            bytes[i*6+4] = (element >> 8) as u8;
            bytes[i*6+5] = element as u8;
        }
        Self(bytes)
    }
}
impl<F:RichField> From<Hash192> for HashOut<F> {
    fn from(hash192: Hash192) -> Self {
        hash192.to_hash_out()
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct MerkleProof<Hash: PartialEq> {
    pub root: Hash,
    pub value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct DeltaMerkleProof<Hash: PartialEq> {
    pub old_root: Hash,
    pub old_value: Hash,

    pub new_root: Hash,
    pub new_value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}

pub trait MerkleHasher<Hash: PartialEq> {
    fn two_to_one(&self, left: &Hash, right: &Hash) -> Hash;
}

pub fn verify_merkle_proof<Hash: PartialEq, Hasher: MerkleHasher<Hash>>(
    hasher: &Hasher,
    proof: MerkleProof<Hash>,
) -> bool {
    let mut current = proof.value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = hasher.two_to_one(sibling, &current);
        } else {
            current = hasher.two_to_one(sibling, &current);
        }
    }
    current == proof.root
}
pub fn verify_delta_merkle_proof<Hash: PartialEq, Hasher: MerkleHasher<Hash>>(
    hasher: &Hasher,
    proof: DeltaMerkleProof<Hash>,
) -> bool {
    let mut current = proof.old_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = hasher.two_to_one(sibling, &current);
        } else {
            current = hasher.two_to_one(sibling, &current);
        }
    }
    if current != proof.old_root {
        return false;
    }
    current = proof.new_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = hasher.two_to_one(sibling, &current);
        } else {
            current = hasher.two_to_one(sibling, &current);
        }
    }
    current == proof.new_root
}

pub type MerkleProof256 = MerkleProof<Hash256>;
pub type DeltaMerkleProof256 = DeltaMerkleProof<Hash256>;

pub type MerkleProof192 = MerkleProof<Hash192>;
pub type DeltaMerkleProof192 = DeltaMerkleProof<Hash192>;

impl MerkleProofSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHashSha2<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &MerkleProof256,
    ) {
        witness.set_hash256_target(&self.value, &merkle_proof.value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash256_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}

impl DeltaMerkleProofSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHashSha2<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &DeltaMerkleProof256,
    ) {
        witness.set_hash256_target(&self.old_value, &merkle_proof.old_value.0);
        witness.set_hash256_target(&self.new_value, &merkle_proof.new_value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash256_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}

impl MerkleProofTruncatedSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHashSha2<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &MerkleProof192,
    ) {
        witness.set_hash192_target(&self.value, &merkle_proof.value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash192_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}

impl DeltaMerkleProofTruncatedSha256Gadget {
    pub fn set_witness_from_proof<F: RichField, W: WitnessHashSha2<F>>(
        &self,
        witness: &mut W,
        merkle_proof: &DeltaMerkleProof192,
    ) {
        witness.set_hash192_target(&self.old_value, &merkle_proof.old_value.0);
        witness.set_hash192_target(&self.new_value, &merkle_proof.new_value.0);
        witness.set_target(self.index, F::from_noncanonical_u64(merkle_proof.index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash192_target(sibling, &merkle_proof.siblings[i].0);
        }
    }
}
