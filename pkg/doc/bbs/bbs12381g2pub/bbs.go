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

	messagesFr, err := messagesToFr(messages)
	if err != nil {
		return fmt.Errorf("parse signature messages: %w", err)
	}

	p1 := signature.A

	q1 := bbs.g2.One()
	bbs.g2.MulScalar(q1, q1, frToRepr(signature.E))
	bbs.g2.Add(q1, q1, publicKey.PointG2)

	p2, err := bbs.getB(signature.S, messagesFr, publicKey)
	if err != nil {
		return fmt.Errorf("get B point: %w", err)
	}

	if compareTwoPairings(p1, q1, p2, bbs.g2.One()) {
		return nil
	}

	return errors.New("BLS12-381: invalid signature")
}

func messagesToFr(messages [][]byte) ([]*SignatureMessage, error) {
	var err error

	messagesFr := make([]*SignatureMessage, len(messages))

	for i := range messages {
		messagesFr[i], err = ParseSignatureMessage(messages[i])
		if err != nil {
			return nil, fmt.Errorf("parse signature message %d: %w", i+1, err)
		}
	}

	return messagesFr, nil
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
	messagesCount := int(uint16FromBytes(proof[0:2]))

	fmt.Printf("messages count: %d\n", messagesCount)

	bitvectorLen := (messagesCount / 8) + 1
	offset := 2 + bitvectorLen

	fmt.Printf("bitvectorLen = %d, offset = %d\n",
		bitvectorLen, offset)

	revealed := bitvectorToIndexes(proof[2:offset])
	fmt.Printf("revealed: %v\n", revealed)

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

	proofNonce, err := ParseProofNonce(nonce)
	if err != nil {
		return fmt.Errorf("parse nonce: %w", err)
	}
	fmt.Printf("proofNonce = %v\n", proofNonce)

	revealedMessages := make(map[int]*SignatureMessage)
	for i := range revealed {
		revealedMessages[revealed[i]] = messagesFr[i]
	}

	h0, h, err := bbs.calcH(publicKey, messagesCount)
	if err != nil {
		return err
	}

	challengeBytes := signatureProof.GetBytesForChallenge(revealed, h0, h)
	proofNonceBytes := frToRepr(proofNonce.fr).ToBytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)

	proofChallenge := frFromOKM(challengeBytes)

	return signatureProof.verify(proofChallenge, publicKey, h0, h, revealedMessages, messagesFr)
	//return errors.New("not implemented")
}

func createRandSignatureFr() (*bls12381.Fr, error) {
	fr, err := bls12381.NewFr().Rand(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("create random FR: %w", err)
	}

	return frToRepr(fr), nil
}

// SignWithKey signs the one or more messages using BBS+ key pair.
func (bbs *BBSG2Pub) SignWithKey(messages [][]byte, privKey *PrivateKey) ([]byte, error) {
	var err error

	pubKey := privKey.PublicKey()

	messagesFr := make([]*SignatureMessage, len(messages))
	for i := range messages {
		messagesFr[i], err = ParseSignatureMessage(messages[i])
		if err != nil {
			return nil, fmt.Errorf("parse signature message %d: %w", i+1, err)
		}
	}

	e, err := createRandSignatureFr()
	if err != nil {
		return nil, fmt.Errorf("create signature.E: %w", err)
	}

	s, err := createRandSignatureFr()
	if err != nil {
		return nil, fmt.Errorf("create signature.S: %w", err)
	}

	b, err := bbs.computeB(s, messagesFr, pubKey)
	if err != nil {
		return nil, fmt.Errorf("compute B point: %w", err)
	}

	exp := bls12381.NewFr().Set(privKey.FR)
	exp.Add(exp, e)
	exp.Inverse(exp)

	sig := bbs.g1.New()
	bbs.g1.MulScalar(sig, b, frToRepr(exp))

	signature := &Signature{
		A: sig,
		E: e,
		S: s,
	}

	return signature.ToBytes()
}

// todo introduce a separate class?
func (bbs *BBSG2Pub) calcH(key *PublicKey, messagesCount int) (*bls12381.PointG1, []*bls12381.PointG1, error) {
	offset := g2UncompressedSize + 1

	data := bbs.calcData(key, messagesCount)

	h0, err := bbs.hashToG1(data)
	if err != nil {
		return nil, nil, fmt.Errorf("create G1 point from hash")
	}

	h := make([]*bls12381.PointG1, messagesCount)

	for i := 1; i <= messagesCount; i++ {
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)

		iBytes := uint32ToBytes(uint32(i))

		for j := 0; j < len(iBytes); j++ {
			dataCopy[j+offset] = iBytes[j]
		}

		h[i-1], err = bbs.hashToG1(dataCopy)
		if err != nil {
			return nil, nil, fmt.Errorf("create G1 point from hash: %w", err)
		}
	}

	return h0, h, nil
}

func (bbs *BBSG2Pub) computeB(s *bls12381.Fr, messages []*SignatureMessage, key *PublicKey) (*bls12381.PointG1, error) {
	const basesOffset = 2

	messagesCount := len(messages)

	bases := make([]*bls12381.PointG1, messagesCount+basesOffset)
	scalars := make([]*bls12381.Fr, messagesCount+basesOffset)

	bases[0] = bbs.g1.One()
	scalars[0] = bls12381.NewFr().RedOne()

	h0, h, err := bbs.calcH(key, messagesCount)
	if err != nil {
		return nil, err
	}

	bases[1] = h0
	scalars[1] = s

	for i := 0; i < len(messages); i++ {
		bases[i+basesOffset] = h[i]
		scalars[i+basesOffset] = messages[i].FR
	}

	res := bbs.g1.Zero()

	for i := 0; i < len(bases); i++ {
		b := bases[i]
		s := scalars[i]

		g := bbs.g1.New()

		bbs.g1.MulScalar(g, b, frToRepr(s))
		bbs.g1.Add(res, res, g)
	}

	return res, nil
}

func (bbs *BBSG2Pub) getB(s *bls12381.Fr, messages []*SignatureMessage, key *PublicKey) (*bls12381.PointG1, error) {
	b, err := bbs.computeB(s, messages, key)
	if err != nil {
		return nil, err
	}

	bbs.g1.Neg(b, b)

	return b, nil
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
