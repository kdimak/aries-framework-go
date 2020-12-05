/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"fmt"
	"math/bits"

	bls12381 "github.com/kilic/bls12-381"
)

type PoKOfSignature struct {
	aPrime *bls12381.PointG1
	aBar   *bls12381.PointG1
	d      *bls12381.PointG1

	pokVC1   *proverCommittedG1
	secrets1 []*bls12381.Fr

	pokVC2   *proverCommittedG1
	secrets2 []*bls12381.Fr

	revealedMessages map[int]*SignatureMessage
}

func NewPoKOfSignature(signature *Signature, messages []*SignatureMessage, revealedIndexes []int, pubKey *PublicKeyWithGenerators) (*PoKOfSignature, error) {
	/*	pubKey.h0 = &bls12381.PointG1{
			{
				16128570759307831335,
				11435327652252418089,
				17181179580529813643,
				7651671045714389869,
				6091123425769061141,
				238155152735112657,
			},
			{
				8852548118187184029,
				1669204339727993791,
				1459831431779159897,
				17438573210797757878,
				2659106277050677739,
				22791677536231356,
			},
			{
				15511072250668529287,
				11066566408031541066,
				16628984762189337385,
				10793151835107043567,
				7193317304276292018,
				1870981874531525183,
			},
		}

		pubKey.h[0] = &bls12381.PointG1{
			{
				8742793826039984843,
				7671088375886345569,
				12031437338403143252,
				15681550841904380983,
				8078050519651180587,
				1477819534017682260,
			},
			{
				16492903571450539607,
				11238088025244284237,
				8359923790576021179,
				5236863890635860287,
				15436933557653648064,
				1587495073999389284,
			},
			{
				9536761074730595784,
				10100421748366638947,
				18163889707563091283,
				2585167595164836700,
				12808825964580439721,
				1104008306170660463,
			},
		}

		pubKey.h[1] = &bls12381.PointG1{
			{
				12584049717995663936,
				16551131396300211555,
				6659348494088217806,
				12324388463641772334,
				18033749704824223396,
				437782960110583554,
			},
			{
				17562697509587597569,
				8619108056400817585,
				4208337652558726328,
				13140242927792930794,
				15253055332162743174,
				265020599723385596,
			},
			{
				7252545001518928562,
				360140954290854271,
				14648341908088101001,
				12124461506902346247,
				8141146677500709250,
				1050445793559046538,
			},
		}*/

	messagesCount := len(messages)

	//err := signature.Verify(messages, pubKey)
	//if err != nil {
	//	return nil, fmt.Errorf("verify input signature: %w", err)
	//}

	//r1, r2 := createRandSignatureFr(), createRandSignatureFr()
	r1 := &bls12381.Fr{
		1504120742137850674,
		17894352453077941349,
		341465311045500809,
		7449983145799358299,
	}

	r2 := &bls12381.Fr{
		10053387086195297902,
		15325863443853508476,
		14992998309415471477,
		5943233445765009386,
	}

	b := computeB(signature.S, messages, pubKey)
	//b := &bls12381.PointG1{
	//	{
	//		4919353811942452779,
	//		1594664523720136443,
	//		4781372093526700820,
	//		10309036171877305459,
	//		13435298166044616736,
	//		1854421087553655826,
	//	},
	//	{
	//		1651584333997501102,
	//		6243631230536078986,
	//		11980491289236877338,
	//		3889014966522092010,
	//		17676356858101210200,
	//		171218091019157395,
	//	},
	//	{
	//		10526952305092756305,
	//		8120995529889985883,
	//		7503702279808081663,
	//		14916900478554174680,
	//		17821696677585582986,
	//		1734336543935554680,
	//	},
	//}

	g1 := bls12381.NewG1()

	aPrime := g1.New()
	g1.MulScalar(aPrime, signature.A, frToRepr(r1))
	//MulScalar(aPrime, signature.A, frToRepr(r1))
	//MulScalar(aPrime, signature.A, frToRepr(r1))

	aBarDenom := g1.New()
	g1.MulScalar(aBarDenom, aPrime, frToRepr(signature.E))

	aBar := g1.New()
	g1.MulScalar(aBar, b, frToRepr(r1))
	g1.Sub(aBar, aBar, aBarDenom)

	r2D := bls12381.NewFr()
	r2D.Neg(r2)

	cb := newCommitmentBuilder(2)
	cb.add(b, r1)
	cb.add(pubKey.h0, r2D)

	d := cb.build() // todo d!
	/*	d = &bls12381.PointG1{
		{
			11329041160047766804,
			14829474186258832103,
			7227898304588376503,
			4194160170757034837,
			16426739371141946610,
			826939733763277989,
		},
		{
			16951474407719173414,
			6376585577275530124,
			12185911854762699975,
			5705324567921146819,
			570174666034630117,
			170448030030821320,
		},
		{
			8369766850028102530,
			18429646314652598620,
			6593225912444047026,
			8974613528098619467,
			3947113440188848756,
			1015062580628640013,
		},
	}*/
	//dAffine := g1.New().Set(d)
	//g1.Affine(dAffine)

	r3 := bls12381.NewFr()
	r3.Inverse(r1)

	sPrime := bls12381.NewFr()
	sPrime.RedMul(r2, r3)
	sPrime.Neg(sPrime)
	sPrime.Add(sPrime, signature.S)

	committing1 := newProverCommittingG1()
	secrets1 := make([]*bls12381.Fr, 2)
	committing1.commit(aPrime)
	sigE := bls12381.NewFr()
	sigE.Neg(signature.E)
	secrets1[0] = sigE
	committing1.commit(pubKey.h0)
	secrets1[1] = r2

	pokVC1 := committing1.finish()
	/*	pokVC1.commitment = &bls12381.PointG1{
		{
			3734058479350625333,
			9978996166412034618,
			11772986047153835249,
			13451970846802567306,
			14047708958769355529,
			378788744374361569,
		},
		{
			12634618621190366289,
			12282151284507742208,
			16755179073830200710,
			8698922424414340193,
			7172720397712984873,
			1674839375548781040,
		},
		{
			18196561215544973602,
			2358624735929929413,
			9832735752356611659,
			3135360501469647193,
			13345763290512590597,
			654068496178333297,
		},
	}*/

	committing2 := newProverCommittingG1()
	secrets2 := make([]*bls12381.Fr, 0, 2+messagesCount)
	committing2.commit(d)
	r3D := bls12381.NewFr()
	r3D.Neg(r3)
	secrets2 = append(secrets2, r3D)
	committing2.commit(pubKey.h0)
	secrets2 = append(secrets2, sPrime)

	revealedMessages := make(map[int]*SignatureMessage, len(revealedIndexes))
	for _, ind := range revealedIndexes {
		revealedMessages[ind] = messages[ind]
	}

	for i := 0; i < messagesCount; i++ {
		if _, ok := revealedMessages[i]; !ok {
			committing2.commit(pubKey.h[i])

			sourceFR := messages[i].FR
			hiddenFRCopy := bls12381.NewFr()
			hiddenFRCopy.Set(sourceFR)

			secrets2 = append(secrets2, hiddenFRCopy)
		}
	}

	pokVC2 := committing2.finish()

	return &PoKOfSignature{
		aPrime:           aPrime,
		aBar:             aBar,
		d:                d,
		pokVC1:           pokVC1,
		secrets1:         secrets1,
		pokVC2:           pokVC2,
		secrets2:         secrets2,
		revealedMessages: revealedMessages,
	}, nil
}

func (pos *PoKOfSignature) Marshal() []byte {
	g1 := bls12381.NewG1()

	challengeBytes := g1.ToUncompressed(pos.aBar)
	challengeBytes = append(challengeBytes, pos.pokVC1.marshal()...)
	challengeBytes = append(challengeBytes, pos.pokVC2.marshal()...)

	return challengeBytes
}

func (pos *PoKOfSignature) generateProof(challengeHash *bls12381.Fr) *PoKOfSignatureProof {
	return &PoKOfSignatureProof{
		aPrime:   pos.aPrime,
		aBar:     pos.aBar,
		d:        pos.d,
		proofVC1: pos.pokVC1.generateProof(challengeHash, pos.secrets1),
		proofVC2: pos.pokVC2.generateProof(challengeHash, pos.secrets2),
	}
}

type proverCommittedG1 struct {
	bases           []*bls12381.PointG1
	blindingFactors []*bls12381.Fr
	commitment      *bls12381.PointG1
}

func (g *proverCommittedG1) marshal() []byte {
	bytes := make([]byte, 0)

	g1 := bls12381.NewG1()

	for _, base := range g.bases {
		bytes = append(bytes, g1.ToUncompressed(base)...)
	}

	return append(bytes, g1.ToUncompressed(g.commitment)...)
}

func (g *proverCommittedG1) generateProof(challenge *bls12381.Fr, secrets []*bls12381.Fr) *ProofG1 {
	responses := make([]*bls12381.Fr, len(g.bases))

	// todo iterate over blindingFactors (for better readability)
	for i := range g.bases {
		c := bls12381.NewFr()
		c.RedMul(challenge, secrets[i])

		s := bls12381.NewFr()
		s.Sub(g.blindingFactors[i], c)
		responses[i] = s
	}

	return &ProofG1{
		commitment: g.commitment,
		responses:  responses,
	}
}

type proverCommittingG1 struct {
	bases           []*bls12381.PointG1
	blindingFactors []*bls12381.Fr
}

func newProverCommittingG1() *proverCommittingG1 {
	return &proverCommittingG1{
		bases:           make([]*bls12381.PointG1, 0),
		blindingFactors: make([]*bls12381.Fr, 0),
	}
}

func (pc *proverCommittingG1) commit(base *bls12381.PointG1) {
	pc.bases = append(pc.bases, base)
	//r := createRandSignatureFr()
	r := &bls12381.Fr{
		10053387086195297902,
		15325863443853508476,
		14992998309415471477,
		5943233445765009386,
	}
	pc.blindingFactors = append(pc.blindingFactors, r)
}

func (pc *proverCommittingG1) finish() *proverCommittedG1 {
	commitment := sumOfG1Products(pc.bases, pc.blindingFactors)

	return &proverCommittedG1{
		bases:           pc.bases,
		blindingFactors: pc.blindingFactors,
		commitment:      commitment,
	}
}

// todo remove this?
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

//func MulScalar(c, p *bls12381.PointG1, e *bls12381.Fr) *bls12381.PointG1 {
//	g := bls12381.NewG1()
//
//	n := &bls12381.PointG1{}
//	n.Set(p)
//
//	res := g.Zero()
//	foundOne := false
//
//	for i := 0; i < 255; i++ {
//		o := e.Bit(i)
//
//		if foundOne {
//			g.Double(res, res)
//		} else {
//			foundOne = o
//		}
//
//		if o {
//			g.Add(res, res, n)
//		}
//	}
//
//	return c.Set(res)
//}

func MulScalar(c, p *bls12381.PointG1, e *bls12381.Fr) *bls12381.PointG1 {
	g1 := bls12381.NewG1()

	q := g1.Zero()

	bitLen := FrBitLen(e)
	fmt.Printf("bitLen = %d\n", bitLen)

	for i := 0; i < bitLen; i++ {
		o := e.Bit(bitLen - i - 1)
		g1.Double(q, q)
		if o {
			g1.Add(q, q, p)
			fmt.Print("1")
		} else {
			fmt.Print("0")
		}
	}
	fmt.Print("\n")

	return c.Set(q)
}

// BitLen counts the number of bits the number is.
func FrBitLen(fr *bls12381.Fr) int {
	ret := 4 * 64
	for i := 3; i >= 0; i-- {
		leading := bits.LeadingZeros64(fr[i])
		ret -= leading
		if leading != 64 {
			break
		}
	}

	return ret
}
