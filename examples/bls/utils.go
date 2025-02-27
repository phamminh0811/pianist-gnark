package main

import (
	"crypto/rand"
	"log"
	"math/big"

	bls12_381_ecc "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12_381_fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var (
	g1Gen bls12_381_ecc.G1Affine
	g2Gen bls12_381_ecc.G2Affine
)

type PrivateKey struct {
	X *big.Int
}

type PublicKey struct {
	P *bls12_381_ecc.G2Affine
}

func init() {
	_, _, g1Gen, g2Gen = bls12_381_ecc.Generators()
}

// BatchGenerateKeyPairs generate BLS private and public key pairs
func BatchGenerateKeyPairs(size int) ([]*PrivateKey, []*PublicKey, error) {
	var privateKeys []*PrivateKey
	var publicKeys []*PublicKey
	for i := 0; i < size; i++ {
		priKey, pubKey, err := GenerateKeyPair()
		if err != nil {
			log.Panicf("GenerateKeyPair failed: %s\n", err)
		}
		privateKeys = append(privateKeys, priKey)
		publicKeys = append(publicKeys, pubKey)
	}
	return privateKeys, publicKeys, nil
}

// GenerateKeyPair generate BLS private and public key pair
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	// generate a random point in G2
	g2Order := bls12_381_fr.Modulus()
	sk, err := rand.Int(rand.Reader, g2Order)
	if err != nil {
		return nil, nil, err
	}

	pk := new(bls12_381_ecc.G2Affine).ScalarMultiplication(&g2Gen, sk)

	priKey := &PrivateKey{X: sk}
	pubKey := &PublicKey{P: pk}

	return priKey, pubKey, nil
}

// Sign BLS signature uses a particular function, defined as:
// S = pk * H(m)
//
// H is a hash function, for instance SHA256 or SM3.
// S is the signature.
// m is the message to sign.
// pk is the private key, which can be considered as a secret big number.
//
// To verify the signature, check that whether the result of e(P, H(m)) is equal to e(G, S) or not.
// Which means that: e(P, H(m)) = e(G, S)
// G is the base point or the generator point.
// P is the public key = pk*G.
// e is a special elliptic curve pairing function which has this feature: e(x*P, Q) = e(P, x*Q).
//
// It is true because of the pairing function described above:
// e(P, H(m)) = e(pk*G, H(m)) = e(G, pk*H(m)) = e(G, S)
func Sign(privateKey *PrivateKey, msg []byte) (blsSignature []byte, err error) {

	hashPointG1, _ := bls12_381_ecc.HashToG1(msg, g1Gen.Marshal())

	sig := new(bls12_381_ecc.G1Affine).ScalarMultiplication(&hashPointG1, privateKey.X)

	return sig.Marshal(), nil
}

func Verify(publicKey *PublicKey, sig, msg []byte) (bool, error) {

	sigPointG1 := new(bls12_381_ecc.G1Affine)
	if err := sigPointG1.Unmarshal(sig); err != nil {
		return false, err
	}

	// e(G, S) = e(S, G)
	lp, err := bls12_381_ecc.Pair([]bls12_381_ecc.G1Affine{*sigPointG1}, []bls12_381_ecc.G2Affine{g2Gen})
	if err != nil {
		return false, err
	}

	// e(P, H(m)) = e(H(m), P)
	hashPointG1, _ := bls12_381_ecc.HashToG1(msg, g1Gen.Marshal())
	rp, err := bls12_381_ecc.Pair([]bls12_381_ecc.G1Affine{hashPointG1}, []bls12_381_ecc.G2Affine{*publicKey.P})
	if err != nil {
		return false, err
	}

	// check whether e(G, S) equals e(P, H(m)) or not
	// if sig is valid, then e(P, H(m)) = e(pk*G, H(m)) = e(G, pk*H(m)) = e(G, S)
	isEqual := lp.Equal(&rp)

	return isEqual, nil
}
