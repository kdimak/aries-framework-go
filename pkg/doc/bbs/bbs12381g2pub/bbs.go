/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"sort"

	bls12381 "github.com/kilic/bls12-381"
	"golang.org/x/crypto/blake2b"
)

// BBSG2Pub defines BBS+ signature scheme where public key is a point in the field of G2.
type BBSG2Pub struct {
	g1 *bls12381.G1
	g2 *bls12381.G2
}

// New creates a new BBSG2Pub.
func New() *BBSG2Pub {
	return &BBSG2Pub{
		g1: bls12381.NewG1(),
		g2: bls12381.NewG2(),
	}
}

const (
	// Signature length.
	bls12381SignatureLen = 112

	// Default BLS 12-381 public key length in G2 field.
	bls12381G2PublicKeyLen = 96

	// Number of bytes in G1 X coordinate.
	g1CompressedSize = 48

	// Number of bytes in G1 X and Y coordinates
	g1UncompressedSize = 96

	// Number of bytes in G2 X(a, b) and Y(a, b) coordinates.
	g2UncompressedSize = 192

	// Number of bytes in scalar compressed form.
	frCompressedSize = 32

	// Number of bytes in scalar uncompressed form.
	frUncompressedSize = 48
)

// Verify makes BLS BBS12-381 signature verification.
func (bbs *BBSG2Pub) Verify(messages [][]byte, sigBytes, pubKeyBytes []byte) error {
	signature, err := ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}

	publicKey, err := UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	messagesCount := len(messages)

	publicKeyWithGenerators, err := publicKey.ToPublicKeyWithGenerators(messagesCount)
	if err != nil {
		return fmt.Errorf("build generators from public key: %w", err)
	}

	messagesFr, err := messagesToFr(messages)
	if err != nil {
		return fmt.Errorf("parse signature messages: %w", err)
	}

	return signature.Verify(messagesFr, publicKeyWithGenerators)
}

// Sign signs the one or more messages using private key in compressed form.
func (bbs *BBSG2Pub) Sign(messages [][]byte, privKeyBytes []byte) ([]byte, error) {
	privKey, err := UnmarshalPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}

	if len(messages) == 0 {
		return nil, errors.New("messages are not defined")
	}

	return bbs.SignWithKey(messages, privKey)
}

func (bbs *BBSG2Pub) VerifyProof(messages [][]byte, proof, nonce, pubKeyBytes []byte) error {
	messagesCount, offset, revealed := bitvectorToRevealed(proof)

	signatureProof, err := ParseSignatureProof(proof[offset:])
	if err != nil {
		return fmt.Errorf("parse compressed signature proof: %w", err)
	}
	fmt.Printf("signatureProof = %v\n", signatureProof)

	messagesFr, err := messagesToFr(messages)
	if err != nil {
		return fmt.Errorf("parse signature messages: %w", err)
	}
	fmt.Printf("messagesFr = %v\n", messagesFr)

	publicKey, err := UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	fmt.Printf("publicKey = %v\n", publicKey)

	publicKeyWithGenerators, err := publicKey.ToPublicKeyWithGenerators(messagesCount)
	if err != nil {
		return fmt.Errorf("build generators from public key: %w", err)
	}

	proofNonce, err := ParseProofNonce(nonce)
	if err != nil {
		return fmt.Errorf("parse nonce: %w", err)
	}
	fmt.Printf("proofNonce = %v\n", proofNonce)

	revealedMessages := make(map[int]*SignatureMessage)
	for i := range revealed {
		revealedMessages[revealed[i]] = messagesFr[i]
	}

	challengeBytes := signatureProof.GetBytesForChallenge(revealed, publicKeyWithGenerators)
	proofNonceBytes := frToRepr(proofNonce.fr).ToBytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)
	proofChallenge := frFromOKM(challengeBytes)

	return signatureProof.verify(proofChallenge, publicKeyWithGenerators, revealedMessages, messagesFr)
}

type ProofMessageType int

const (
	Revealed ProofMessageType = iota + 1
	Hidden
)

type ProofMessage struct {
	message     *SignatureMessage
	messageType ProofMessageType
}

func (bbs *BBSG2Pub) DeriveProof(messages [][]byte, sigBytes, nonce, pubKeyBytes []byte, revealedIndexes []int) ([]byte, error) {
	if len(revealedIndexes) == 0 {
		return nil, errors.New("no message to reveal")
	}

	sort.Ints(revealedIndexes)

	messagesCount := len(messages)

	bitvector := revealedToBitvector(messagesCount, revealedIndexes)
	fmt.Printf("bitvector (%d): %v\n", len(bitvector), bitvector)

	messagesFr, err := messagesToFr(messages)
	if err != nil {
		return nil, fmt.Errorf("parse signature messages: %w", err)
	}
	fmt.Printf("messagesFr = %v\n", messagesFr)

	publicKey, err := UnmarshalPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	fmt.Printf("publicKey = %v\n", publicKey)

	publicKeyWithGenerators, err := publicKey.ToPublicKeyWithGenerators(messagesCount)
	if err != nil {
		return nil, fmt.Errorf("build generators from public key: %w", err)
	}

	signature, err := ParseSignature(sigBytes)
	if err != nil {
		return nil, fmt.Errorf("parse signature: %w", err)
	}
	fmt.Printf("signature = %v\n", signature)

	pokSignature, err := NewPoKSignature(signature, messagesFr, revealedIndexes, publicKeyWithGenerators)
	if err != nil {
		return nil, fmt.Errorf("init proof of knowledge signature: %w", err)
	}
	fmt.Printf("pokSignature = %v\n", pokSignature)

	return nil, errors.New("not implemented")
}

func createRandSignatureFr() *bls12381.Fr {
	fr, _ := bls12381.NewFr().Rand(rand.Reader) //nolint:errcheck

	return frToRepr(fr)
}

// SignWithKey signs the one or more messages using BBS+ key pair.
func (bbs *BBSG2Pub) SignWithKey(messages [][]byte, privKey *PrivateKey) ([]byte, error) {
	var err error

	pubKey := privKey.PublicKey()
	messagesCount := len(messages)
	pubKeyWithGenerators, err := pubKey.ToPublicKeyWithGenerators(messagesCount)
	if err != nil {
		return nil, fmt.Errorf("build generators from public key: %w", err)
	}

	messagesFr := make([]*SignatureMessage, len(messages))
	for i := range messages {
		messagesFr[i], err = ParseSignatureMessage(messages[i])
		if err != nil {
			return nil, fmt.Errorf("parse signature message %d: %w", i+1, err)
		}
	}

	e, s := createRandSignatureFr(), createRandSignatureFr()
	exp := bls12381.NewFr().Set(privKey.FR)
	exp.Add(exp, e)
	exp.Inverse(exp)

	sig := bbs.g1.New()
	b := computeB(s, messagesFr, pubKeyWithGenerators)
	bbs.g1.MulScalar(sig, b, frToRepr(exp))

	signature := &Signature{
		A: sig,
		E: e,
		S: s,
	}

	return signature.ToBytes()
}

func computeB(s *bls12381.Fr, messages []*SignatureMessage, key *PublicKeyWithGenerators) *bls12381.PointG1 {
	const basesOffset = 2

	cb := newCommitmentBuilder(len(messages) + basesOffset)
	g1 := bls12381.NewG1()

	cb.add(g1.One(), bls12381.NewFr().RedOne())
	cb.add(key.h0, s)

	for i := 0; i < len(messages); i++ {
		cb.add(key.h[i], messages[i].FR)
	}

	return cb.build()
}

type commitmentBuilder struct {
	bases   []*bls12381.PointG1
	scalars []*bls12381.Fr
}

func newCommitmentBuilder(expectedSize int) *commitmentBuilder {
	return &commitmentBuilder{
		bases:   make([]*bls12381.PointG1, 0, expectedSize),
		scalars: make([]*bls12381.Fr, 0, expectedSize),
	}
}

func (cb *commitmentBuilder) add(base *bls12381.PointG1, scalar *bls12381.Fr) {
	cb.bases = append(cb.bases, base)
	cb.scalars = append(cb.scalars, scalar)
}

func (cb *commitmentBuilder) build() *bls12381.PointG1 {
	return sumOfG1Products(cb.bases, cb.scalars)
}

func sumOfG1Products(bases []*bls12381.PointG1, scalars []*bls12381.Fr) *bls12381.PointG1 {
	g1 := bls12381.NewG1()
	res := g1.Zero()

	for i := 0; i < len(bases); i++ {
		b := bases[i]
		s := scalars[i]

		g := g1.New()

		g1.MulScalar(g, b, frToRepr(s))
		g1.Add(res, res, g)
	}

	return res
}

func getB(s *bls12381.Fr, messages []*SignatureMessage, key *PublicKeyWithGenerators) *bls12381.PointG1 {
	b := computeB(s, messages, key)

	g1 := bls12381.NewG1()
	g1.Neg(b, b)

	return b
}

func (bbs *BBSG2Pub) calcData(key *PublicKey, messagesCount int) []byte {
	data := bbs.g2.ToUncompressed(key.PointG2)

	data = append(data, 0, 0, 0, 0, 0, 0)

	mcBytes := uint32ToBytes(uint32(messagesCount))

	data = append(data, mcBytes...)

	return data
}

func (bbs *BBSG2Pub) hashToG1(data []byte) (*bls12381.PointG1, error) {
	dstG1 := []byte("BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0")

	newBlake2b := func() hash.Hash {
		// We pass a null key so error is impossible here.
		h, _ := blake2b.New512(nil) //nolint:errcheck
		return h
	}

	return bbs.g1.HashToCurve(newBlake2b, data, dstG1)
}

func compareTwoPairings(p1 *bls12381.PointG1, q1 *bls12381.PointG2,
	p2 *bls12381.PointG1, q2 *bls12381.PointG2) bool {
	engine := bls12381.NewEngine()

	engine.AddPair(p1, q1)
	engine.AddPair(p2, q2)

	return engine.Check()
}
