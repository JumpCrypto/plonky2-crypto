use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;


use super::sha256::{WitnessHashSha2};
use super::sha256_truncated::CircuitBuilderTruncatedSha2;
use super::{CircuitBuilderHash, Hash192Target, WitnessHash};

pub fn compute_merkle_root<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    index_bits: &Vec<BoolTarget>,
    value: Hash192Target,
    siblings: &Vec<Hash192Target>,
) -> Hash192Target {
    let mut current = value;
    for (i, sibling) in siblings.iter().enumerate() {
        let bit = index_bits[i];

        let left = builder.select_hash192( bit, *sibling, current);
        let right = builder.select_hash192(bit, current, *sibling);
        current = builder.two_to_one_truncated_sha256(left, right);
    }
    current
}

pub struct MerkleProofTruncatedSha256Gadget {
    pub root: Hash192Target,
    pub value: Hash192Target,
    pub siblings: Vec<Hash192Target>,
    pub index: Target,
}

impl MerkleProofTruncatedSha256Gadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings: Vec<Hash192Target> = (0..height)
            .map(|_| builder.add_virtual_hash192_target())
            .collect();

        let value = builder.add_virtual_hash192_target();
        let index = builder.add_virtual_target();
        let index_bits = builder.split_le(index, height);
        let root = compute_merkle_root(builder, &index_bits, value, &siblings);

        Self {
            root,
            value,
            siblings,
            index,
        }
    }

    pub fn set_witness<F: RichField, W: WitnessHashSha2<F>>(
        &self,
        witness: &mut W,
        index: u64,
        value: &[u8; 24],
        siblings: &Vec<[u8; 24]>,
    ) {
        witness.set_hash192_target(&self.value, value);
        witness.set_target(self.index, F::from_noncanonical_u64(index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash192_target(sibling, &siblings[i]);
        }
    }
}

pub struct DeltaMerkleProofTruncatedSha256Gadget {
    pub old_root: Hash192Target,
    pub old_value: Hash192Target,

    pub new_root: Hash192Target,
    pub new_value: Hash192Target,

    pub siblings: Vec<Hash192Target>,
    pub index: Target,
}

impl DeltaMerkleProofTruncatedSha256Gadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        height: usize,
    ) -> Self {
        let siblings: Vec<Hash192Target> = (0..height)
            .map(|_| builder.add_virtual_hash192_target())
            .collect();

        let old_value = builder.add_virtual_hash192_target();
        let new_value = builder.add_virtual_hash192_target();
        let index = builder.add_virtual_target();
        let index_bits = builder.split_le(index, height);
        let old_root = compute_merkle_root(builder, &index_bits, old_value, &siblings);
        let new_root = compute_merkle_root(builder, &index_bits, new_value, &siblings);

        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            siblings,
            index,
        }
    }

    pub fn set_witness<F: RichField, W: WitnessHashSha2<F>>(
        &self,
        witness: &mut W,
        index: u64,
        old_value: &[u8; 24],
        new_value: &[u8; 24],
        siblings: &Vec<[u8; 24]>,
    ) {
        witness.set_hash192_target(&self.old_value, old_value);
        witness.set_hash192_target(&self.new_value, new_value);
        witness.set_target(self.index, F::from_noncanonical_u64(index));
        for (i, sibling) in self.siblings.iter().enumerate() {
            witness.set_hash192_target(sibling, &siblings[i]);
        }
    }
}
pub fn compute_merkle_root_truncated_sha256<F: RichField+Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, leaves: &[Hash192Target]) -> Hash192Target{
  if (leaves.len() as f64).log2().ceil() != (leaves.len() as f64).log2().floor(){
    panic!("The length of the merkle tree's leaves array must be a power of 2 (2^n)");
  }
  let num_levels = (leaves.len() as f64).log2().ceil() as usize;
  let mut current = leaves.to_vec();
  for _ in 0..num_levels{
    let tmp = current.chunks_exact(2).map(|f| builder.two_to_one_truncated_sha256(f[0], f[1])).collect();
    current = tmp;

  }
  current[0]
}
#[cfg(test)]
mod tests {

    use crate::hash::sha256_truncated_merkle::{DeltaMerkleProofTruncatedSha256Gadget, MerkleProofTruncatedSha256Gadget};
    use crate::hash::{CircuitBuilderHash, WitnessHash};
    use crate::hash::merkle_utils::{MerkleProof192, DeltaMerkleProof192};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    const SMALL_MERKLE_PROOFS: &str = r#"
    [
      {
        "root": "8ce47831fa9e8fc6dc2631cc676d8392313f7228bf2628d0",
        "siblings": [
          "93a7b526b4539b1519c03dc81b1f92ed31acbdadb8c930be",
          "81201c69c29f02d7015cc2564db231c5ac5d07c24bbd06a4",
          "e4c0e62041f91b6c90bd2832182b3a52b1c334f398f0246c",
          "f1dde9ea14d2ee93786d7d5e8f04d5ac19143e6d3cf21ada",
          "da0d5558f7797e3a37b1ee3c6fe1da0fac6589ef0ec85121"
        ],
        "index": 15,
        "value": "6c652a08d06186cdf550f67eda642202cbe4c747716ed550"
      },
      {
        "root": "5313e65c747b7c7aa81b5fefedf42b10c9333327cb07af34",
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "fe46d376e67c2254694c347d0afe236b75336490394afb0d",
          "e99a7762a88398781a5033622920f7ab6718257eb19ccca9",
          "b7df18f989925b15e03bec732cf46af8e0c2a9c6050e9dfb",
          "5befbf2e8a1a141cf6133d8e8129f32e78ac61062f9a239f"
        ],
        "index": 29,
        "value": "000000000000000000000000000000000000000000000000"
      },
      {
        "root": "ced84c2700c11e72495a35caa606019609794dda50caaddd",
        "siblings": [
          "77ee6c1b0b7e95bbca3ff6a34445b079668467912bb47500",
          "9bfd545a14fc6572c898eb9200a84b2e454b972b3905cbc0",
          "1e09e6cb66cec2c8a92a4fc345376be6d6b4c4c0570ed781"
        ],
        "index": 4,
        "value": "43c8b70308380de1224d64d7196760ab2a06f47085ff13df"
      },
      {
        "root": "ced84c2700c11e72495a35caa606019609794dda50caaddd",
        "siblings": [
          "521a640c1caafc21a4bd6b48ced3d60c3aeacf2ab5ea09ba",
          "14a1c68279ad393d4bd7625b065bf17c10fe13ca0f27f492",
          "e854c3850894f7a5a7cc74cffaa7d8d646972f5b4d6ee8b9"
        ],
        "index": 1,
        "value": "f071d559a4d8f6014f9ad03f7b0121a01518341694529897"
      },
      {
        "root": "79666b3e60a7f629ab7622a0f5df5fd84005a288134d959b",
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "c2a103ad1e2e923fc1993318a63ea714eda3630d4680dd78",
          "68a957640671cd2073f5b043482bf9e35d02339bcd5c03e9",
          "a88c2f54b0bc3e9d50f58c1d4811cf266af5b0cface893bc"
        ],
        "index": 6,
        "value": "8fb2d850018d9f09aabe74babdd26395c52ba6c36bcc27ed"
      },
      {
        "root": "79666b3e60a7f629ab7622a0f5df5fd84005a288134d959b",
        "siblings": [
          "be4b9875a18800889c3e66552b6397a6b25db7652563f299",
          "f94127607bd87b313aebb372b36cba913d95fca15e6d74a1",
          "1da273ba38b033fa58b4754e8d689f0c2b6a12026cc511fd",
          "a88c2f54b0bc3e9d50f58c1d4811cf266af5b0cface893bc"
        ],
        "index": 0,
        "value": "e12a01166536ec83377a1ce0918a6c5a0b89ff823f4062cf"
      },
      {
        "root": "dc7429c8e343c23fbaabc16b83739454632ed633311a7aef",
        "siblings": [
          "42c3ae0c727ee637ee564133dfbbedbcf2555f5f1534b4cd",
          "4ee11667fe4b4b5947959535fa03e1489ee13c09fd2794e9",
          "9ea75858f5c3b2538398d172aecec24232c52fcd63ae9fff"
        ],
        "index": 6,
        "value": "6bbe9138924947c94509a6d0f7390e98dca63a38d326bfdf"
      },
      {
        "root": "dc7429c8e343c23fbaabc16b83739454632ed633311a7aef",
        "siblings": [
          "3027eac7dc2a14ef779a04e66203ce16ae3bf95472b766a8",
          "813eb55b59a858f2b28d926102a30fa6aa0468091e6d9988",
          "c1f1a1d1638e9761f1677268b53e38bb44c036ae116a9bed"
        ],
        "index": 1,
        "value": "a9611ac7ab506b57cee7c38b3b83715eaa08aa0d77bcf61f"
      },
      {
        "root": "a8c4553513d62785d0765b29d53cfa46fea878378f95c7e9",
        "siblings": [
          "4c264204a6eb3a88d3e3cbfa06f0a4b486f01055cb82c10e",
          "321d0799406db01521c341d23bd7314968b5cba8b3d46eb8"
        ],
        "index": 3,
        "value": "0ec33d7d3c23c18a4144b88201f4cde556cae5dfb1916891"
      },
      {
        "root": "a8c4553513d62785d0765b29d53cfa46fea878378f95c7e9",
        "siblings": [
          "30a6ef35e30168d832e97cd4fed35220a2f3009a21a430a9",
          "c5b3c3bb728f1c6c4021ba924602a843ea6b7df205793664"
        ],
        "index": 1,
        "value": "bdeaea5c0c08869c53a36a8e7644f7ebebf6e32be2e5cfcb"
      },
      {
        "root": "28bbb2970f9a64051670779baf00d3db0ccb613a484a4fc5",
        "siblings": [
          "c296afe32a478134777b6b0588a2c9b1f86a3a0bfa55c625",
          "6b4c3568c45cc4d3026388c71be5411466b491148788fd23",
          "f783c89a5c67bdc98466dae1ec56b0efba582892780e20d0"
        ],
        "index": 3,
        "value": "cc10f18b06dd6365366690550c48c947fd8144c11cc976be"
      },
      {
        "root": "28bbb2970f9a64051670779baf00d3db0ccb613a484a4fc5",
        "siblings": [
          "f76a0a71f724c37b8eed0be4280b9c2b668b53dc862a5ceb",
          "7815cc410f24f77e9384d63e8efc187e86bb4d8187b70050",
          "409e63f8d1c7c2ca2da8a7d2c56ece3aa40eb0cd420b261f"
        ],
        "index": 5,
        "value": "e1a9ddd171e191ed2e9e34bbb3a1b2e665e65b750bdfa6b7"
      },
      {
        "root": "afce7d182834e48a88d45db6c3833ad51ceb60e5e5caa5e2",
        "siblings": [
          "f2f55ffbf696831576323d0bfac6710073e8ce7694eae99f",
          "d52c0c15507beee68123f8dd38a28eccc1f56de03388cfa0",
          "4e0fac824e2dfbbca047d85c6f05c523e3db2e31ac6d75d6"
        ],
        "index": 4,
        "value": "775aca6a322df3887dc19fe7da4b262b9dc02c3650630bf3"
      },
      {
        "root": "afce7d182834e48a88d45db6c3833ad51ceb60e5e5caa5e2",
        "siblings": [
          "e6aeed73c5843735fb3ac567abd4dbcfb894f7c5659b5e86",
          "ee53fc721f076d76ab64c995aa23d4a54382d82f27954b15",
          "943e3435a20752cc53ce03215c535e8b9c21016a7016df71"
        ],
        "index": 0,
        "value": "1de9f130254ec6a8ee3a8df8a539a205b3509ab0e3bff6cf"
      },
      {
        "root": "be224af255dd6bf53d56738040a8207bf8bb98027b59ae61",
        "siblings": [
          "b9f754b505eff11d424c1e6983a0db68b0c54b0bb6ae1059",
          "cc9181ae4127c5c8ee4b3d1adae560e09d3293acccd9b7e5",
          "4819814478941d48d8921a7b289b79c2709622517f826f56",
          "66341692f46741c611a709596135b09f4842ecca593f08a3"
        ],
        "index": 14,
        "value": "380f2b167ce130efcd797b77fb3eba3e18539a7bf3fe8772"
      },
      {
        "root": "be224af255dd6bf53d56738040a8207bf8bb98027b59ae61",
        "siblings": [
          "64fb394242203a7771adfeed453965654d3397f6c797ea13",
          "4ec9ff57795e4ccb7507c7f0e98fd18a9b47ad911df71c11",
          "e9cb96ba853ed70ffe9c3a0ddbf4ccc43770a278a01938db",
          "489c8649984fe624e6eee7588b8bde493c05e486e73023da"
        ],
        "index": 1,
        "value": "8bd918726e6167d1db01ba26a54cfc2b2d50c126381955ad"
      }
    ]
    "#;

    const SMALL_DELTA_MERKLE_PROOFS: &str = r#"
    [
      {
        "index": 0,
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "df99695b9d441940e4e1adf727dc1c48d06f54afc9b2ffa6"
        ],
        "old_root": "8bb06fd2062223553c51e18f916a7ea2b3e519f400c4ddf6",
        "old_value": "000000000000000000000000000000000000000000000000",
        "new_value": "4b4b4ee152393271516423e92114bee4079859d0738e2e68",
        "new_root": "0e3aa6291d830f230dbe50907d496f4688527c6ad7fef833"
      },
      {
        "index": 2,
        "siblings": [
          "29337a6b91d34765a42d322b50c5fc673f9a8155dada38d5",
          "946660c9cd5c7116aa281248fdbf20c510ac65a85cea7e89"
        ],
        "old_root": "c35efd846a566c448964eaddbb0a0021abf18bc89476f631",
        "old_value": "467ee0cb54eb282384b15acd57563d70839f6a9353655657",
        "new_value": "9bdad0b5266866eb4ff6a4a5c89dbed940ccacf10db82d1f",
        "new_root": "f4c133e368fea599142cbf639a67d5870c06eefd671fb284"
      },
      {
        "index": 16,
        "siblings": [
          "a636b48f4ba58651e9f5ffa75917a28d6a92805d7707246c",
          "17b0761f87b081d5cf10757ccc89f12be355c70e2e29df28",
          "5b253a40fe440e2c1240afc1bc1ebdb355fce135f0d99097",
          "5a5c27f6767ebefeeb36acf5cb5bc978a52a9256e71e44b2",
          "34be2b390cd59779ee74f2942d2ba3f12176d07bb746b2af"
        ],
        "old_root": "adf4d0fd2a199895ae9193fdaab7d36ec080e75e420b160f",
        "old_value": "644108dd19e5a1f405c56fd6df1c6ff1c610b7d42561af2f",
        "new_value": "98cbbdaaa136ff0c42c34c07fcd876355df87052b6da63b9",
        "new_root": "de664d9bf989519d291363272520bb5d216fd20688e2b1b0"
      },
      {
        "index": 0,
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "17b0761f87b081d5cf10757ccc89f12be355c70e2e29df28",
          "5b253a40fe440e2c1240afc1bc1ebdb355fce135f0d99097",
          "f88fc9dc701329cbc8b855d67d4ad10e02190fdfeb78e6bb",
          "c277b62cd67e797e7b5c7142c392ca47a3730b399df2a0f4"
        ],
        "old_root": "58b53b7ec1ae789137bff540511a52b5a666c6bd9efb4b53",
        "old_value": "000000000000000000000000000000000000000000000000",
        "new_value": "045ace8b8f1a87385c3907241b5741e4b443ccb75e38b63f",
        "new_root": "c442c624e211aeb65a0e20750c9d7255c99e1fdff2b1dca8"
      },
      {
        "index": 6,
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "17b0761f87b081d5cf10757ccc89f12be355c70e2e29df28",
          "c205db5acaeee273bf4a36c2b9bb786d60400daaaab97077",
          "7f3640fc38c1888f8bcb4fd91074f16fb99e4479bc8aa6c8",
          "98e9ecb812ba1e96b20606c27b8baa95ac514cf8328c2d8f"
        ],
        "old_root": "e91eb054d74f257cf29734126e9f5fe1190f1f25cbf00e6a",
        "old_value": "5b181ca38a95331682ed666298af3a1773d21208ef4571d6",
        "new_value": "9935a6359038a6750966c9e2dd0327c6cf2f0d7ffe5110b8",
        "new_root": "75d66f9f33bb0a68cec9ded2b140c60800fa9a8941cabc87"
      },
      {
        "index": 23,
        "siblings": [
          "bcee8bc9cf701c33085580d858b6c765ec6172db34cfa62d",
          "e6680586a8925814396a8611a8a14e5c6a739cac0b24b374",
          "dbed913941a5d383bfe8f22c8ac0aab233ce2f4dda92ad9d",
          "8a67de69396927030e297acdea71f1a5bdf026dc373f618f",
          "119e81ebc51feea64117661eb263678b9a2acda0e363a704"
        ],
        "old_root": "9befd18443b5a9ff4d056fc460f35d4e9fcb7ecb2a81742d",
        "old_value": "abbfbf7fa78e9fc73267cf4ad0254cb9c4a35c7006b26b3b",
        "new_value": "4b8ad08f621022e95cb7e57522ebee76c77902d0f2c88a05",
        "new_root": "61cea17b1e4e18cb3d1f970b2a9765c76e84f80202dffefc"
      },
      {
        "index": 3,
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "537509bc887735cd284909580e34e43c8aa3c46d8387c02d",
          "9ff7cf34f94da25dfb5e354b0776f964e9fecf0de81e2509",
          "cacb3ca2589221d459911a0e7bff3f0a62e7c85016e239bb",
          "53464025934ba9b24b98b99e1337f106a29aa94a404aab2f"
        ],
        "old_root": "13a0c9fa7de022658f8c29dcb8c3ef6aeaa5c0e82ea07d41",
        "old_value": "000000000000000000000000000000000000000000000000",
        "new_value": "b9b94fe36a7188868d7392f98d776c3daa9cc2eff31e9d8f",
        "new_root": "545f9896f215d23ea516851799412c2d0fd41a079a3c75c7"
      },
      {
        "index": 25,
        "siblings": [
          "b5bbc9ca920933ceb3157330fbd9bd8edf919efdb8dfe7c8",
          "a470094ab070ab1ce6fc218b5d593d247649d96be90d93ef",
          "167ee6a38a2e85b19f00973df3960aa3badf70af7e3b9d23",
          "feb9ea7befe2cf08484efb33e8485cc6cfb617b01fa1b505",
          "13af4f8d184975534e42840c30d0a2804ba0037d0fe6a333"
        ],
        "old_root": "d30ef4068a30505322dc4576f2a4b701f5b76dc87f83f10a",
        "old_value": "000000000000000000000000000000000000000000000000",
        "new_value": "fa8828e6d55156099c625f3144404003415074d48e27f90d",
        "new_root": "4a9a6660a3b067e8afa015c80bbdcc2359e90e2569b7bc66"
      },
      {
        "index": 15,
        "siblings": [
          "a6c8ac63d731870f83d045771fa54a551dc1ec90e973b3d6",
          "5032aa0ed7644cfabb2cf73de88333901529e8dca34fa39c",
          "5b253a40fe440e2c1240afc1bc1ebdb355fce135f0d99097",
          "b50764d3cc0bc182c92679736f9fba7d47c14485af1234aa",
          "7ce1decb1e7d9eb29cb5000fa5d42ff5e0c08bc91d47677d"
        ],
        "old_root": "8539ae1b0468cd7b8738f79531b28481e17fa5d794809eac",
        "old_value": "3bf9c5a574d3897537c6068dfc474ecb72a1024a61cb6d11",
        "new_value": "5c4c7561bcf9cf2f0e376d226335dd506af9baed711222d1",
        "new_root": "7ea8cdb533fa66abaa413e60a5e93f38e0b808204a42b340"
      },
      {
        "index": 6,
        "siblings": [
          "000000000000000000000000000000000000000000000000",
          "10e359b3140973a869c54130413af692214a3434853475ca",
          "fea97c7b334d36f915a6664d5ca24a9d6b8a7f99c4106c9f",
          "2e1b582854d0d65efc1c38ee2ae12bf8bf68d3579703ec6b",
          "7ce1decb1e7d9eb29cb5000fa5d42ff5e0c08bc91d47677d"
        ],
        "old_root": "7ea8cdb533fa66abaa413e60a5e93f38e0b808204a42b340",
        "old_value": "ea932d6176fdbc36b6ff23d181ae07074517ceb6fbdc283d",
        "new_value": "e0f5e8fe395b2b7c7fbd13c31c9203551f51845be96ba07e",
        "new_root": "779452dad24be67db48d6ef8d5a4badfc040f1daa164c72e"
      },
      {
        "index": 13,
        "siblings": [
          "297d38dcc9c0a1db5d0a82a2a04d4a32fa52ba843a1aa732",
          "bedf6a6fc5b02b1d73661400155c1b249514deac6d4deb57",
          "b288da51d73ea51f75ab1bfd61e0fe006dc646a1f102e3b8",
          "6004dbf8bd6cf6b8483adc0bcd5e86fe8935f15f00059e8e"
        ],
        "old_root": "cd9c40176fd925daf613c897b9c121f26a315003f826308b",
        "old_value": "57598afea9d52df5e9fab747fa91e87357965670fc6b08a4",
        "new_value": "7055dc8053550062d278ee5da44c64d1e201e8bddec0a4a3",
        "new_root": "36091ce0057a596db89a6c3a6678c1b2fe05d1be78da0b88"
      },
      {
        "index": 5,
        "siblings": [
          "bbfe8a0bba40939c061e2153b2b59e2d25a3a2f0cbaabcdb",
          "ce586b1ce6f10beeacc41857c223d3a2fc108da3050a5ed6",
          "5b253a40fe440e2c1240afc1bc1ebdb355fce135f0d99097",
          "fea5eb2983a9bded7d01cd0332c3aa66718954b5e6e5b851"
        ],
        "old_root": "7a9061a251cae7c17305150835fe1e7d21dc0803cf42455a",
        "old_value": "000000000000000000000000000000000000000000000000",
        "new_value": "305c9a542e6840fdeadafeb72efbf6e9b17d23635b4e4cf0",
        "new_root": "eeaee4014b5be08e28eec7adefd38b37888a4623f29f5997"
      }
    ]
    "#;

    #[test]
    fn test_verify_small_merkle_proofs() {
        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;


        let parsed_proofs: Vec<MerkleProof192> = serde_json::from_str(SMALL_MERKLE_PROOFS).unwrap();
        for proof in parsed_proofs {

            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let merkle_proof_gadget = MerkleProofTruncatedSha256Gadget::add_virtual_to(&mut builder, proof.siblings.len());
            let expected_root_target = builder.add_virtual_hash192_target();
            builder.connect_hash192(expected_root_target, merkle_proof_gadget.root);
            let num_gates = builder.num_gates();
            let data = builder.build::<C>();
            println!(
                "MerkleProofTruncatedSha256Gadget (height = {}) circuit num_gates={}, quotient_degree_factor={}",
                proof.siblings.len(), num_gates, data.common.quotient_degree_factor
            );
            
            let mut pw = PartialWitness::new();
            merkle_proof_gadget.set_witness_from_proof(&mut pw, &proof);
            pw.set_hash192_target(&expected_root_target, &proof.root.0);

            let start_time = std::time::Instant::now();

            let proof = data.prove(pw).unwrap();
            let duration_ms = start_time.elapsed().as_millis();
            println!("proved in {}ms", duration_ms);
            assert!(data.verify(proof).is_ok());
        }
    }


    #[test]
    fn test_verify_small_delta_merkle_proofs() {
        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;


        let parsed_proofs: Vec<DeltaMerkleProof192> = serde_json::from_str(SMALL_DELTA_MERKLE_PROOFS).unwrap();
        for proof in parsed_proofs {

            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let delta_merkle_proof_gadget = DeltaMerkleProofTruncatedSha256Gadget::add_virtual_to(&mut builder, proof.siblings.len());
            let expected_old_root_target = builder.add_virtual_hash192_target();
            let expected_new_root_target = builder.add_virtual_hash192_target();
            builder.connect_hash192(expected_old_root_target, delta_merkle_proof_gadget.old_root);
            builder.connect_hash192(expected_new_root_target, delta_merkle_proof_gadget.new_root);
            let num_gates = builder.num_gates();
            let data = builder.build::<C>();
            println!(
                "DeltaMerkleProofTruncatedSha256Gadget (height = {}) circuit num_gates={}, quotient_degree_factor={}",
                proof.siblings.len(), num_gates, data.common.quotient_degree_factor
            );
            
            let mut pw = PartialWitness::new();
            delta_merkle_proof_gadget.set_witness_from_proof(&mut pw, &proof);
            pw.set_hash192_target(&expected_old_root_target, &proof.old_root.0);
            pw.set_hash192_target(&expected_new_root_target, &proof.new_root.0);

            let start_time = std::time::Instant::now();

            let proof = data.prove(pw).unwrap();
            let duration_ms = start_time.elapsed().as_millis();
            println!("proved in {}ms", duration_ms);
            assert!(data.verify(proof).is_ok());
        }
    }


}
