/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"crypto/rand"
	"fmt"

	bls12381 "github.com/kilic/bls12-381"
	"golang.org/x/crypto/blake2b"
)

func parseFr(data []byte) *bls12381.Fr {
	return bls12381.NewFr().RedFromBytes(data)
}

func f2192() *bls12381.Fr {
	return &bls12381.Fr{0, 0, 0, 1}
}

func frFromOKM(message []byte) *bls12381.Fr {
	const (
		eightBytes = 8
		okmMiddle  = 24
	)

	// We pass a null key so error is impossible here.
	h, _ := blake2b.New384(nil) //nolint:errcheck

	// blake2b.digest() does not return an error.
	_, _ = h.Write(message) //nolint:errcheck
	okm := h.Sum(nil)
	emptyEightBytes := make([]byte, eightBytes)

	elm := bls12381.NewFr().RedFromBytes(append(emptyEightBytes, okm[:okmMiddle]...))
	elm.Mul(elm, f2192())

	fr := bls12381.NewFr().RedFromBytes(append(emptyEightBytes, okm[okmMiddle:]...))
	elm.Add(elm, fr)

	return elm
}

func frToRepr(fr *bls12381.Fr) *bls12381.Fr {
	frRepr := bls12381.NewFr()
	frRepr.RedMul(fr, &bls12381.Fr{1})

	return frRepr
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

func createRandSignatureFr() *bls12381.Fr {
	fr, _ := bls12381.NewFr().Rand(rand.Reader) //nolint:errcheck

	return frToRepr(fr)
}
