# Hello Plonky2!

A simple example to get started with Plonky2 and Plonky2-Crypto library.

This example features:
- Minimal `Cargo.toml` to get started
- Minimal `.cargo` to avoid performance degradation
- Library structure, so you can publish your circuit and reuse it (even contribute it to plonky2-crypto!)
- Example on how to write a `CircuitBuilder`
- Example on how to write tests, by build your circuit (done once) and generating zero knowledge proofs (one per test case). 

To run the example:
```
cargo test --release -- --nocapture
```
(don't forget the `--release`!)
