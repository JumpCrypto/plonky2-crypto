use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{RichField, HashOutTarget};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::hash::CircuitBuilderHash;
use crate::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};

use super::sha256::{
    big_sigma, ch, maj, sha256_round_constants, sha256_start_state, sigma, CircuitBuilderHashSha2,
};
use super::{Hash192Target};

pub trait CircuitBuilderTruncatedSha2<F: RichField + Extendable<D>, const D: usize> {
    fn truncated_sha256(&mut self, data: &[U32Target]) -> Hash192Target;
    fn two_to_one_truncated_sha256(
        &mut self,
        left: Hash192Target,
        right: Hash192Target,
    ) -> Hash192Target;
    fn truncated_sha256_hash_out(&mut self, data: &[U32Target]) -> HashOutTarget;
    fn two_to_one_truncated_sha256_hash_out(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
    ) -> HashOutTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderTruncatedSha2<F, D>
    for CircuitBuilder<F, D>
{
    fn truncated_sha256(&mut self, data: &[U32Target]) -> Hash192Target {
        let result = self.hash_sha256_u32(data);
        [
            result[0],
            result[1],
            result[2],
            result[3],
            result[4],
            result[5],
        ]
    }

    fn two_to_one_truncated_sha256(
        &mut self,
        left: Hash192Target,
        right: Hash192Target,
    ) -> Hash192Target {
        let state = sha256_start_state(self);
        let k256 = sha256_round_constants(self);

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        let zero = self.constant_u32(0);
        let cx80 = self.constant_u32(0x80000000);
        let c384 = self.constant_u32(384); // 192+192
                                           // Process the 384-bit message
        let mut w: [U32Target; 16] = [
            left[0], left[1], left[2], left[3], left[4], left[5], right[0], right[1], right[2],
            right[3], right[4], right[5], cx80, zero, zero, c384,
        ];

        for i in 0..64 {
            // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
            if i >= 16 {
                let s0 = sigma(self, w[(i + 1) & 0xf], 7, 18, 3);
                let s1 = sigma(self, w[(i + 14) & 0xf], 17, 19, 10);
                w[i & 0xf] = self.add_many_u32(&[s0, s1, w[(i + 9) & 0xf], w[i & 0xf]]).0;
            }

            // Compression function main loop
            let big_s1_e = big_sigma(self, e, 6, 11, 25);
            let ch_efg = ch(self, e, f, g);
            let temp1 = self
                .add_many_u32(&[h, big_s1_e, ch_efg, k256[i], w[i & 0xf]])
                .0;

            let big_s0_a = big_sigma(self, a, 2, 13, 22);
            let maj_abc = maj(self, a, b, c);
            let temp2 = self.add_u32_lo(big_s0_a, maj_abc);

            h = g;
            g = f;
            f = e;
            e = self.add_u32_lo(d, temp1);
            d = c;
            c = b;
            b = a;
            a = self.add_u32_lo(temp1, temp2); // add_many_u32 of 3 elements is the same
        }

        // Add the compressed chunk to the current hash value
        [
            self.add_u32_lo(state[0], a),
            self.add_u32_lo(state[1], b),
            self.add_u32_lo(state[2], c),
            self.add_u32_lo(state[3], d),
            self.add_u32_lo(state[4], e),
            self.add_u32_lo(state[5], f),
        ]
    }

    fn truncated_sha256_hash_out(&mut self, data: &[U32Target]) -> HashOutTarget {
        let result = self.truncated_sha256(data);
        self.hash192_to_hash_out(result)
    }

    fn two_to_one_truncated_sha256_hash_out(
        &mut self,
        left: HashOutTarget,
        right: HashOutTarget,
    ) -> HashOutTarget {
        let left_192 = self.hash_out_to_hash192(left);
        let right_192 = self.hash_out_to_hash192(right);

        
        let result = self.two_to_one_truncated_sha256(left_192, right_192);
        self.hash192_to_hash_out(result)
    }
}



#[cfg(test)]
mod tests {
    use std::time::Instant;

    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::hash::merkle_utils::{Hash192};
    use crate::hash::sha256_truncated::CircuitBuilderTruncatedSha2;
    use crate::hash::{CircuitBuilderHash, WitnessHash};
    

    #[test]
    fn test_truncated_sha256_two_to_one() {
        let tests = [
            [
              "AFCD4BF774D5F2D3FEED035DB36A740A446864124673227D",
              "BA14D0B2ABF1D369F5BE1730997F9E77540A0C435133064F",
              "461075FD679C0863B99A0E3498EA3CACD0A007DEA9DBF572"
            ],
            [
              "43FB6415E33BBE716607A4B9A78B6625E5A776D8A37B185A",
              "F0214D64F35C43C30D92E812DECC4658A4EDAD0850228E99",
              "D660BADE6D0BC67250ED87D0EEEA427D5B6B9E7B4CAAC6EE"
            ],
            [
              "04340EC34E8C8E38152B45CD9BBDC305FE595E198722E7BF",
              "A3895951755CE2125584A94B588E66F3C1F64D8B9D50F6BD",
              "08844DE6B4C4D009A12E79A196292F1C6E52AF610D9D3044"
            ],
            [
              "58464F7B9347A7573FD8F7FA0155A9E3556EC47C1A7A5F19",
              "B54136795B6E3E479B3A4526ED8CC15B9729AD3EABA1CBAE",
              "002D28DAC7C0194F4BC15BE3DF0D3CBC885523F3FAAED111"
            ],
            [
              "9506324C7EFCC3863BA92D5871AA182D2B1E63D93EE960AD",
              "279C6B519973869ADD01CF6D0249BE105C27AF6297EE5C32",
              "8349F52C81D5C7FA81AE1880158E65C8BB1514BC23A03EB6"
            ],
            [
              "91CE20D131F9ACBDE60CB946AA1A54901C9E71E93EC4B2AD",
              "027E9C142D0E0225F137E13955EF406BE18B6245DE0DE80A",
              "59E5A7FED5282B26FB7E4751B22B8CEF568B4C4666435D37"
            ],
            [
              "88BE9D9F512FD105DBABD7C25849BABAE1E5882A7FC1DADA",
              "D6F6F3BAE52B7D4A6C8AADDB01FAF0D0911EAF0DFA7121C9",
              "96D7429D88AC980A57459EC9FBD92BB9DD253C178E0C2416"
            ],
            [
              "C6E60652FAFFE4B4D62B84B4F904150397B39E5B99944B29",
              "A0C6245E473D897A6C7C46DBACDCDEF4ECACF28694862D65",
              "7B54D7CC33C2354268B263DBAF74E89D68480FF102315002"
            ],
            [
              "877908AD071DD2C83C7E31B1F2926B76DBA622F0C3FF5511",
              "938944FC9145B545465E3ED63DE4227D2A57712972C7533B",
              "E98BA96CCBD96AFC0593A17A0225E42C244C4A7B9661F532"
            ],
            [
              "B0DC39A30D1F5992DFD0B022DA2FED3F047466832ECA1FBE",
              "3F90165ED38AF49C8DC66DE4A79B8620A7AA8893E9B38630",
              "B6D9032CBA848F5416DA5F6395E02F477AE58F608F360026"
            ],
            [
              "C63897AFB82F3A2D138EFA68C1C52D796C7676017CD2601E",
              "7AA288423DE03FF0E403D696454E29895757A7F5BFF37B78",
              "63F674231847641F9E323932AD0AF2C3D1EE356E9500CDCD"
            ],
            [
              "7A1606CEA3FC417C4014C6FDB5C37C469285E3E9E33FF6DC",
              "E924482BCCAA627C2C78D9767794E23F7FA41ECFF69C3E24",
              "4D41A244BD66D71D3998A0DD1345D3D3C679A0EAB340C8C7"
            ]
        ];

        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let left_target = builder.add_virtual_hash192_target();
        let right_target = builder.add_virtual_hash192_target();
        let expected_output_target = builder.add_virtual_hash192_target();
        let output_target = builder.two_to_one_truncated_sha256(left_target, right_target);
        builder.connect_hash192(output_target, expected_output_target);

        let num_gates = builder.num_gates();
        // let copy_constraints = builder.copy_constraints.len();
        let copy_constraints = "<private>";
        let data = builder.build::<C>();
        println!(
            "two_to_one_truncated_sha256 num_gates={}, copy_constraints={}, quotient_degree_factor={}",
            num_gates, copy_constraints, data.common.quotient_degree_factor
        );

        for t in tests {
            let left = Hash192::from_str(t[0]).unwrap();
            let right = Hash192::from_str(t[1]).unwrap();
            let expected_output = Hash192::from_str(t[2]).unwrap();

            // test circuit
            let mut pw = PartialWitness::new();
            pw.set_hash192_target(&left_target, &left.0);
            pw.set_hash192_target(&right_target, &right.0);
            pw.set_hash192_target(&expected_output_target, &expected_output.0);
            let start = Instant::now();
            let proof = data.prove(pw).unwrap();
            let end = start.elapsed();
            println!("two_to_one_truncated_sha256 of proved in {}ms", end.as_millis());
            assert!(data.verify(proof).is_ok());
        }
    }

}
