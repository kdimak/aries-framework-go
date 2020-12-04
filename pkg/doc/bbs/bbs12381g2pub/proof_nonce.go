/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import bls12381 "github.com/kilic/bls12-381"

type ProofNonce struct {
	fr *bls12381.Fr
}

func ParseProofNonce(proofNonceBytes []byte) *ProofNonce {
	return &ProofNonce{
		frFromOKM(proofNonceBytes),
	}
}

func (pn *ProofNonce) ToBytes() []byte {
	return frToRepr(pn.fr).ToBytes()
}
