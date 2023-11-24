use std::time::Instant;

use bellpepper_core::{num::AllocatedNum, SynthesisError};
use ff::PrimeField;
use flate2::{write::ZlibEncoder, Compression};
use nova_snark::{
  provider::pasta::{PallasEngine, VestaEngine},
  traits::{
    circuit::{StepCircuit, TrivialCircuit},
    snark::default_ck_hint,
    Engine,
  },
  CompressedSNARK, PublicParams, RecursiveSNARK,
};

type E1 = PallasEngine;
type E2 = VestaEngine;

//  output[0] = input[0] +  a
//  output[1] = input[0] +  input[1]
#[derive(Debug, Clone)]
struct AlgebraCircuit<F: PrimeField> {
  a: F,
}

impl<F: PrimeField> StepCircuit<F> for AlgebraCircuit<F> {
  fn arity(&self) -> usize {
    2
  }

  fn synthesize<CS: bellpepper_core::ConstraintSystem<F>>(
    &self,
    cs: &mut CS,
    z: &[AllocatedNum<F>],
  ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let input_0 = z[0].clone();
    let input_1 = z[1].clone();

    let a = AllocatedNum::alloc(cs.namespace(|| format!("data")), || Ok(self.a))?;

    let output_0 = input_0.add(cs.namespace(|| format!("add")), &a)?;
    let output_1 = input_0.add(cs.namespace(|| format!("add")), &input_1)?;

    Ok(vec![output_0, output_1])
  }
}

fn main() {
  let num_steps = 5usize;

  //   input[0]  input[1]  data
  //    10         20       0
  //    10         30       1
  //    11         40       2
  //    13         51       3
  //    16         64       4
  //    20         80

  let mut circuits_primary = vec![];
  for i in 0..num_steps {
    circuits_primary.push(AlgebraCircuit {
      a: <E1 as Engine>::Scalar::from(i as u64),
    })
  }

  let circuit_secondary = TrivialCircuit::default();

  // produce public parameters
  let start = Instant::now();
  println!("Producing public parameters...");
  let pp = PublicParams::<
    E1,
    E2,
    AlgebraCircuit<<E1 as Engine>::Scalar>,
    TrivialCircuit<<E2 as Engine>::Scalar>,
  >::setup(
    &circuits_primary[0],
    &circuit_secondary,
    &*default_ck_hint(),
    &*default_ck_hint(),
  );
  println!("PublicParams::setup, took {:?} ", start.elapsed());

  println!(
    "Number of constraints per step (primary circuit): {}",
    pp.num_constraints().0
  );
  println!(
    "Number of constraints per step (secondary circuit): {}",
    pp.num_constraints().1
  );

  println!(
    "Number of variables per step (primary circuit): {}",
    pp.num_variables().0
  );
  println!(
    "Number of variables per step (secondary circuit): {}",
    pp.num_variables().1
  );

  let z0_primary = vec![
    <E1 as Engine>::Scalar::from(10),
    <E1 as Engine>::Scalar::from(20),
  ];
  let z0_secondary = vec![<E2 as Engine>::Scalar::zero()];

  type C1 = AlgebraCircuit<<E1 as Engine>::Scalar>;
  type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;
  // produce a recursive SNARK
  println!("Generating a RecursiveSNARK...");
  let mut recursive_snark: RecursiveSNARK<E1, E2, C1, C2> = RecursiveSNARK::<E1, E2, C1, C2>::new(
    &pp,
    &circuits_primary[0],
    &circuit_secondary,
    &z0_primary,
    &z0_secondary,
  )
  .unwrap();

  for (i, circuit_primary) in circuits_primary.iter().enumerate() {
    let start = Instant::now();
    let res = recursive_snark.prove_step(&pp, circuit_primary, &circuit_secondary);
    assert!(res.is_ok());
    println!(
      "RecursiveSNARK::prove_step {}: {:?}, took {:?} ",
      i,
      res.is_ok(),
      start.elapsed()
    );
  }

  // verify the recursive SNARK
  println!("Verifying a RecursiveSNARK...");
  let start = Instant::now();
  let res = recursive_snark.verify(&pp, num_steps, &z0_primary, &z0_secondary);
  println!(
    "RecursiveSNARK::verify: {:?}, took {:?}",
    res.is_ok(),
    start.elapsed()
  );
  assert!(res.is_ok());

  // produce a compressed SNARK
  println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
  let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();

  let start = Instant::now();
  type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<E1>;
  type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
  type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;
  type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

  let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
  println!(
    "CompressedSNARK::prove: {:?}, took {:?}",
    res.is_ok(),
    start.elapsed()
  );
  assert!(res.is_ok());
  let compressed_snark = res.unwrap();

  let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
  bincode::serialize_into(&mut encoder, &compressed_snark).unwrap();
  let compressed_snark_encoded = encoder.finish().unwrap();
  println!(
    "CompressedSNARK::len {:?} bytes",
    compressed_snark_encoded.len()
  );

  // verify the compressed SNARK
  println!("Verifying a CompressedSNARK...");
  let start = Instant::now();
  let res = compressed_snark.verify(&vk, num_steps, &z0_primary, &z0_secondary);
  println!(
    "CompressedSNARK::verify: {:?}, took {:?}",
    res.is_ok(),
    start.elapsed()
  );
  assert!(res.is_ok());
  println!("=========================================================");
}
