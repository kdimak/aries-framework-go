/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"errors"
	"fmt"

	bls12381 "github.com/kilic/bls12-381"
)

type PoKSignature struct {
	aPrime *bls12381.PointG1
	aBar   *bls12381.PointG1
	d      *bls12381.PointG1

	pokVC1   *ProverCommittedG1
	secrets1 []*bls12381.Fr

	pokVC2   *ProverCommittedG1
	secrets2 []*bls12381.Fr

	revealedMessages map[int]*SignatureMessage
}

type ProverCommittedG1 struct {
	bases           []*bls12381.PointG1
	blindingFactors []*bls12381.Fr
	commitment      *bls12381.G1
}

func NewPoKSignature(signature *Signature, messages []*SignatureMessage, revealedIndexes []int, pubKey *PublicKeyWithGenerators) (*PoKSignature, error) {
	err := signature.Verify(messages, pubKey)
	if err != nil {
		return nil, fmt.Errorf("verify input signature: %w", err)
	}

	r1, r2 := createRandSignatureFr(), createRandSignatureFr()

	b := getB(signature.S, messages, pubKey)

	g1 := bls12381.NewG1()

	aPrime := g1.New()
	g1.MulScalar(aPrime, signature.A, r1)

	aBarDenom := g1.New()
	g1.MulScalar(aBarDenom, aPrime, signature.E)

	aBar := g1.New()
	g1.MulScalar(aBar, b, r1)
	g1.Sub(aBar, aBar, aBarDenom)

	r2D := bls12381.NewFr()
	r2.Neg(r2D)

	cb := newCommitmentBuilder(2)
	cb.add(b, r1)
	cb.add(pubKey.h0, r1)

	//d := cb.build()

	r3 := bls12381.NewFr()
	r1.Inverse(r3)

	sPrime := bls12381.NewFr()
	r2.Mul(sPrime, r3)
	sPrime.Neg(sPrime)
	sPrime.Add(sPrime, signature.S)

	committing1 := newProverCommittingG1()
	secrets1 := make([]*bls12381.Fr, 2)
	committing1.commit(aPrime)
	sigE := bls12381.NewFr()
	signature.E.Neg(sigE)
	secrets1[0] = sigE
	committing1.commit(pubKey.h0)
	secrets1[1] = r2

	// let pok_vc_1 = committing_1.finish();

	//proofMessages := getProofMessages(messages, revealedIndexes)

	return nil, errors.New("not implemented")
}

type proverCommittingG1 struct {
	bases           []*bls12381.PointG1
	blindingFactors []*bls12381.Fr
}

func (pc *proverCommittingG1) commit(base *bls12381.PointG1) {
	pc.bases = append(pc.bases, base)
	pc.blindingFactors = append(pc.blindingFactors, createRandSignatureFr())
}

func newProverCommittingG1() *proverCommittingG1 {
	return &proverCommittingG1{
		bases:           make([]*bls12381.PointG1, 0),
		blindingFactors: make([]*bls12381.Fr, 0),
	}
}

func getProofMessages(messages []*SignatureMessage, revealedIndexes []int) []ProofMessage {
	proofMessages := make([]ProofMessage, len(messages))
	for i := range messages {
		proofMessages[i] = ProofMessage{
			message:     messages[i],
			messageType: Hidden,
		}
	}

	for _, revealedInd := range revealedIndexes {
		proofMessages[revealedInd].messageType = Revealed
	}

	return proofMessages
}
