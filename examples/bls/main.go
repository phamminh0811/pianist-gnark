package main

import (
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	sw_bn254_ecc "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// BlsCircuit Boneh-Lynn-Shacham (BLS) signature verification
// e(sig, g2) * e(hm, pk) == 1
// where:
//   - Sig (in G1) the signature
//   - G2 (in G2) the public generator of G2
//   - Hm (in G1) the hashed-to-curve message
//   - Pk (in G2) the public key of the signer
type BlsCircuit struct {
	Sig sw_bn254_ecc.G1Affine
	G2  sw_bn254_ecc.G2Affine
	Hm  sw_bn254_ecc.G1Affine
	Pk  sw_bn254_ecc.G2Affine
}

// Define e(sig,g2) * e(hm,pk) == 1
func (circuit *BlsCircuit) Define(api frontend.API) error {
	pl, _ := sw_bn254_ecc.Pair([]sw_bn254_ecc.G1Affine{circuit.Sig}, []sw_bn254_ecc.G2Affine{circuit.G2})
	pr, _ := sw_bn254_ecc.Pair([]sw_bn254_ecc.G1Affine{circuit.Hm}, []sw_bn254_ecc.G2Affine{circuit.Pk})
	
	if !pl.Equal(&pr) {
		panic("sig verify not match")
	}
	return nil

}

func main() {
	start := time.Now()
	circuit := BlsCircuit{}
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Panic("frontend Compile err: ", err)
	}
	// Create  Pair  privateKey and PublicKey
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		log.Panic("GenerateKeyPair err: ", err)
	}
	msg := []byte("Sig Test")
	hm, err := sw_bn254_ecc.HashToG1(msg, g1Gen.Marshal())
	if err != nil {
		log.Panic("HashToG1 err: ", err)
	}
	sig := new(sw_bn254_ecc.G1Affine).ScalarMultiplication(&hm, privateKey.X)
	circuit = BlsCircuit{
		Sig: *sig,
		G2:  g2Gen,
		Hm:  hm,
		Pk:  *publicKey.P,
	}

	// groth16 zkSNerrRK: Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Panicf("Failed to Setup err: %s", err)
	}
	// witness definition
	witness, err := frontend.NewWitness(&circuit, ecc.BN254)
	if err != nil {
		log.Panicf("Failed to create witness err: %s", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		log.Panicf("Failed to create witness Public err: %s", err)
	}

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Panicf("Prove err: %s", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Panicf("Verify err: %s", err)
	}

	elapsed := time.Since(start)
	fmt.Println("Prove took %s", elapsed)
}
