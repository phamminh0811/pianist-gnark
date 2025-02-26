package bls

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
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

type Signature struct {
	S []byte
}

func init() {
	_, _, g1Gen, g2Gen = bls12_381_ecc.Generators()
}

// generate BLS private and public key pair
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

// BLS signature uses a particular function, defined as:
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
	hPoint := hashToG1(msg)
	sig := new(bls12_381_ecc.G1Affine).ScalarMultiplication(hPoint, privateKey.X)

	blsSig := &Signature{
		S: sig.Marshal(),
	}

	// convert the signature to json format
	sigContent, err := json.Marshal(blsSig)
	if err != nil {
		return nil, err
	}

	return sigContent, nil
}

func Verify(publicKey *PublicKey, sig, msg []byte) (bool, error) {
	signature := new(Signature)
	if err := json.Unmarshal(sig, signature); err != nil {
		return false, fmt.Errorf("failed unmashalling bls signature [%s]", err)
	}

	sigPointG1 := new(bls12_381_ecc.G1Affine)
	if err := sigPointG1.Unmarshal(signature.S); err != nil {
		return false, err
	}

	// e(G, S) = e(S, G)
	lp, err := bls12_381_ecc.Pair([]bls12_381_ecc.G1Affine{*sigPointG1}, []bls12_381_ecc.G2Affine{g2Gen})
	if err != nil {
		return false, err
	}

	// e(P, H(m)) = e(H(m), P)
	hashPointG1 := hashToG1(msg)
	rp, err := bls12_381_ecc.Pair([]bls12_381_ecc.G1Affine{*hashPointG1}, []bls12_381_ecc.G2Affine{*publicKey.P})
	if err != nil {
		return false, err
	}

	// check whether e(G, S) equals e(P, H(m)) or not
	// if sig is valid, then e(P, H(m)) = e(pk*G, H(m)) = e(G, pk*H(m)) = e(G, S)
	isEqual := lp.Equal(&rp)

	return isEqual, nil
}

func hashToG1(msg []byte) *bls12_381_ecc.G1Affine {
	// hash a msg to a point of G1
	k := HashUsingSha256(msg)
	intK := new(big.Int).SetBytes(k)

	return new(bls12_381_ecc.G1Affine).ScalarMultiplication(&g1Gen, intK)
}
func HashUsingSha256(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	out := h.Sum(nil)

	return out
}
