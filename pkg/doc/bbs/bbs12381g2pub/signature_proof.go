/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"encoding/binary"
	"errors"
	"fmt"

	bls12381 "github.com/kilic/bls12-381"
)

// PoKOfSignatureProof defines BLS signature proof.
// It is the actual proof that is sent from prover to verifier.
type PoKOfSignatureProof struct {
	aPrime *bls12381.PointG1
	aBar   *bls12381.PointG1
	d      *bls12381.PointG1

	proofVC1 *ProofG1
	proofVC2 *ProofG1
}

func (sp *PoKOfSignatureProof) GetBytesForChallenge(revealed []int, publicKey *PublicKeyWithGenerators) []byte {
	g1 := bls12381.NewG1()

	hiddenCount := publicKey.messagesCount - len(revealed)

	bytesLen := (7 + hiddenCount) * g1UncompressedSize
	bytes := make([]byte, 0, bytesLen)

	revealedMap := make(map[int]bool)
	for _, r := range revealed {
		revealedMap[r] = true
	}

	bytes = append(bytes, g1.ToUncompressed(sp.aBar)...)
	bytes = append(bytes, g1.ToUncompressed(sp.aPrime)...)
	bytes = append(bytes, g1.ToUncompressed(publicKey.h0)...)
	bytes = append(bytes, g1.ToUncompressed(sp.proofVC1.commitment)...)
	bytes = append(bytes, g1.ToUncompressed(sp.d)...)
	bytes = append(bytes, g1.ToUncompressed(publicKey.h0)...)

	for i := range publicKey.h {
		if _, ok := revealedMap[i]; !ok {
			bytes = append(bytes, g1.ToUncompressed(publicKey.h[i])...)
		}
	}

	bytes = append(bytes, g1.ToUncompressed(sp.proofVC2.commitment)...)

	return bytes
}

func (sp *PoKOfSignatureProof) verify(challenge *bls12381.Fr, publicKey *PublicKeyWithGenerators,
	revealedMessages map[int]*SignatureMessage, messagesFr []*SignatureMessage) error {
	g1, g2 := bls12381.NewG1(), bls12381.NewG2()

	aBar := new(bls12381.PointG1)
	g1.Neg(aBar, sp.aBar)

	ok := compareTwoPairings(sp.aPrime, publicKey.w, aBar, g2.One())
	if !ok {
		return errors.New("bad signature")
	}

	bases := []*bls12381.PointG1{sp.aPrime, publicKey.h0}
	aBarD := new(bls12381.PointG1)
	g1.Sub(aBarD, sp.aBar, sp.d)

	err := sp.proofVC1.verify(bases, aBarD, challenge)
	if err != nil {
		return errors.New("bad signature (vc1)")
	}

	revealedMessagesCount := len(revealedMessages)

	basesVc2 := make([]*bls12381.PointG1, 0, 2+publicKey.messagesCount-revealedMessagesCount)
	basesVc2 = append(basesVc2, sp.d)
	basesVc2 = append(basesVc2, publicKey.h0)

	basesDisclosed := make([]*bls12381.PointG1, 0, 1+revealedMessagesCount)
	exponents := make([]*bls12381.Fr, 0, 1+revealedMessagesCount)
	basesDisclosed = append(basesDisclosed, g1.One())
	exponents = append(exponents, bls12381.NewFr().RedOne())

	messagesFrInd := 0
	for i := range publicKey.h {
		if _, ok := revealedMessages[i]; ok {
			basesDisclosed = append(basesDisclosed, publicKey.h[i])
			exponents = append(exponents, messagesFr[messagesFrInd].FR)
			messagesFrInd++
		} else {
			basesVc2 = append(basesVc2, publicKey.h[i])
		}
	}

	pr := g1.Zero()
	for i := 0; i < len(basesDisclosed); i++ {
		b := basesDisclosed[i]
		s := exponents[i]

		g := g1.New()

		g1.MulScalar(g, b, frToRepr(s))
		g1.Add(pr, pr, g)
	}

	g1.Neg(pr, pr)

	err = sp.proofVC2.verify(basesVc2, pr, challenge)
	if err != nil {
		return errors.New("bad signature (vc2)")
	}

	return nil
}

func (sp *PoKOfSignatureProof) ToBytes() []byte {
	bytes := make([]byte, 0)

	g1 := bls12381.NewG1()

	aPrimeBytes := g1.ToCompressed(sp.aPrime)
	fmt.Printf("aPrimeBytes=%v\n", aPrimeBytes)
	bytes = append(bytes, aPrimeBytes...)

	aBarBytes := g1.ToCompressed(sp.aBar)
	fmt.Printf("aBarBytes=%v\n", aBarBytes)
	bytes = append(bytes, aBarBytes...)

	dBytes := g1.ToCompressed(sp.d)
	fmt.Printf("dBytes=%v\n", dBytes)
	bytes = append(bytes, dBytes...)

	proof1Bytes := sp.proofVC1.ToBytes()
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(proof1Bytes)))
	fmt.Printf("proof1BytesLen=%d\n", len(proof1Bytes))
	fmt.Printf("proof1Bytes=%v\n", proof1Bytes)
	//proof1Bytes = []byte{162, 22, 96, 35, 159, 112, 119, 125, 176, 143, 145, 194, 225, 230, 120, 206, 12, 147, 14, 149, 233, 5, 24, 106, 141, 86, 153, 235, 52, 193, 241, 88, 147, 147, 98, 158, 78, 216, 166, 51, 222, 151, 161, 105, 106, 254, 96, 213, 0, 0, 0, 2, 8, 28, 90, 47, 106, 137, 195, 45, 221, 235, 200, 20, 173, 31, 242, 124, 124, 16, 2, 249, 141, 14, 136, 47, 147, 48, 56, 242, 209, 156, 125, 113, 70, 185, 167, 24, 214, 10, 120, 78, 69, 42, 164, 90, 138, 190, 207, 64, 88, 241, 183, 112, 242, 197, 100, 72, 81, 82, 65, 22, 131, 177, 88, 212}
	bytes = append(bytes, lenBytes...)
	bytes = append(bytes, proof1Bytes...)

	bytes = append(bytes, sp.proofVC2.ToBytes()...)

	return bytes
}

type ProofG1 struct {
	commitment *bls12381.PointG1
	responses  []*bls12381.Fr
}

func (pg1 *ProofG1) verify(bases []*bls12381.PointG1, commitment *bls12381.PointG1, challenge *bls12381.Fr) error {
	contribution := pg1.getChallengeContribution(bases, commitment, challenge)
	fmt.Printf("contribution = %v\n", contribution)

	g1 := bls12381.NewG1()
	g1.Sub(contribution, contribution, pg1.commitment)

	if !g1.IsZero(contribution) {
		return errors.New("contribution is not zero")
	}

	return nil
}

func (pg1 *ProofG1) getChallengeContribution(bases []*bls12381.PointG1, commitment *bls12381.PointG1, challenge *bls12381.Fr) *bls12381.PointG1 {
	points := append(bases, commitment)
	scalars := append(pg1.responses, challenge)

	return sumOfG1Products(points, scalars)

	//g1 := bls12381.NewG1()
	//
	//res := g1.Zero()
	//
	//for i := 0; i < len(points); i++ {
	//	b := points[i]
	//	s := scalars[i]
	//
	//	g := g1.New()
	//
	//	g1.MulScalar(g, b, frToRepr(s))
	//	g1.Add(res, res, g)
	//}
	//
	//return res
}

func (pg1 *ProofG1) ToBytes() []byte {
	bytes := make([]byte, 0)

	g1 := bls12381.NewG1()

	commitmentBytes := g1.ToCompressed(pg1.commitment)
	fmt.Printf("commitmentBytes=%v\n", commitmentBytes)
	bytes = append(bytes, commitmentBytes...)

	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(pg1.responses)))
	bytes = append(bytes, lenBytes...)

	for i := range pg1.responses {
		responseBytes := frToRepr(pg1.responses[i]).ToBytes()
		fmt.Printf("response[%d]=%v\n", i, responseBytes)
		bytes = append(bytes, responseBytes...)
	}

	return bytes
}

func ParseSignatureProof(sigProofBytes []byte) (*PoKOfSignatureProof, error) {
	if len(sigProofBytes) < g1CompressedSize*3 {
		return nil, errors.New("invalid size of signature proof")
	}

	fmt.Printf("signature proof data (%d): %v\n", len(sigProofBytes), sigProofBytes)

	g1 := bls12381.NewG1()

	g1Points := make([]*bls12381.PointG1, 3)
	offset := 0

	for i := range g1Points {
		g1Point, err := g1.FromCompressed(sigProofBytes[offset : offset+g1CompressedSize])
		if err != nil {
			return nil, fmt.Errorf("parse G1 point: %w", err)
		}

		g1Points[i] = g1Point
		offset += g1CompressedSize
	}

	proof1BytesLen := int(uint32FromBytes(sigProofBytes[offset : offset+4]))
	offset += 4
	fmt.Printf("proof1BytesLen=%d\n", proof1BytesLen)
	fmt.Printf("proof1Bytes=%v\n", sigProofBytes[offset:offset+proof1BytesLen])

	proofVc1, err := ParseProofG1(sigProofBytes[offset : offset+proof1BytesLen])
	if err != nil {
		return nil, fmt.Errorf("parse G1 proof: %w", err)
	}
	offset += proof1BytesLen

	proofVc2, err := ParseProofG1(sigProofBytes[offset:])
	if err != nil {
		return nil, fmt.Errorf("parse G1 proof: %w", err)
	}

	return &PoKOfSignatureProof{
		aPrime:   g1Points[0],
		aBar:     g1Points[1],
		d:        g1Points[2],
		proofVC1: proofVc1,
		proofVC2: proofVc2,
	}, nil
}

func ParseProofG1(bytes []byte) (*ProofG1, error) {
	if len(bytes) < g1CompressedSize+4 {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	g1 := bls12381.NewG1()
	offset := 0

	commitment, err := g1.FromCompressed(bytes[:g1CompressedSize])
	if err != nil {
		return nil, fmt.Errorf("parse G1 point: %w", err)
	}

	offset += g1CompressedSize
	length := int(uint32FromBytes(bytes[offset : offset+4]))
	offset += 4

	if len(bytes) < g1CompressedSize+4+length*frCompressedSize {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	responses := make([]*bls12381.Fr, length)
	for i := 0; i < length; i++ {
		responses[i] = parseFr(bytes[offset : offset+frCompressedSize])
		offset += frCompressedSize
	}

	return &ProofG1{
		commitment: commitment,
		responses:  responses,
	}, nil
}
