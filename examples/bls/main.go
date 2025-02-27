package main

import (
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	bls381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	bls12381 "github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
)

// Circuit Boneh-Lynn-Shacham (BLS) signature verification
// e(sig, g2) == e(hm, pk)
// where:
//   - Sig (in G1) the signature
//   - G2 (in G2) the public generator of G2
//   - Hm (in G1) the hashed-to-curve message
//   - Pk (in G2) the public key of the signer
type Circuit struct {
	Sig bls12381.G1Affine
	G2  bls12381.G2Affine
	Hm  bls12381.G1Affine
	Pk  bls12381.G2Affine
}

// Define e(sig,g2) == e(hm,pk)
func (circuit *Circuit) Define(api frontend.API) error {
	pair, _ := bls12381.NewPairing(api)
	pl, _ := pair.Pair([]*bls12381.G1Affine{&circuit.Sig}, []*bls12381.G2Affine{&circuit.G2})
	pr, _ := pair.Pair([]*bls12381.G1Affine{&circuit.Hm}, []*bls12381.G2Affine{&circuit.Pk})
	pair.AssertIsEqual(pl, pr)

	return nil
}

func main() {
	start := time.Now()
	circuit := Circuit{}
	ccs, _ := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	// Create Pair privateKey and PublicKey
	privateKey, PublicKey, err := GenerateKeyPair()
	if err != nil {
		log.Panic("GenerateKeyPair err: ", err)
	}

	msg := []byte("Sig Test")
	hm, err := bls381.HashToG1(msg, g1Gen.Marshal())
	if err != nil {
		log.Panic("HashToG1 err: ", err)
	}

	sig := new(bls381.G1Affine).ScalarMultiplication(&hm, privateKey.X)
	circuit = Circuit{
		Sig: bls12381.NewG1Affine(*sig),
		G2:  bls12381.NewG2Affine(g2Gen),
		Hm:  bls12381.NewG1Affine(hm),
		Pk:  bls12381.NewG2Affine(*PublicKey.P),
	}

	// witness definition
	witness, _ := frontend.NewWitness(&circuit, ecc.BLS12_381.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16 zkSNerrRK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Panic("Setup err: ", err)
	}
	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Panic("Prove err: ", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Panic("Verify err: ", err)
	}

	elapsed := time.Since(start)
	fmt.Println("Prove took %s", elapsed)
}
