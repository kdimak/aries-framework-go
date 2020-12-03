/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"encoding/binary"
	"fmt"
)

func uint32ToBytes(value uint32) []byte {
	bytes := make([]byte, 4)

	binary.BigEndian.PutUint32(bytes, value)

	return bytes
}

func uint16FromBytes(bytes []byte) uint16 {
	return binary.BigEndian.Uint16(bytes)
}

func uint32FromBytes(bytes []byte) uint32 {
	return binary.BigEndian.Uint32(bytes)
}

func bitvectorToIndexes(data []byte) []int {
	revealedIndexes := make([]int, 0)

	scalar := 0
	for _, v := range data {
		remaining := 8

		for v > 0 {
			revealed := v & 1
			if revealed == 1 {
				revealedIndexes = append(revealedIndexes, scalar)
			}

			v >>= 1
			scalar += 1
			remaining -= 1
		}

		scalar += remaining
	}

	return revealedIndexes
}

func revealedToBitvector(messagesCount int, revealed []int) []byte {
	bitvectorLen := (messagesCount / 8) + 1
	totalLen := 2 + bitvectorLen

	bytes := make([]byte, totalLen)
	bitvector := bytes[2:]

	for _, r := range revealed {
		idx := r / 8
		bit := r % 8

		bitvector[idx] |= 1 << bit
	}

	binary.BigEndian.PutUint16(bytes, uint16(messagesCount))

	return bytes
}

func bitvectorToRevealed(bitvector []byte) (int, int, []int) {
	messagesCount := int(uint16FromBytes(bitvector[0:2]))

	fmt.Printf("messages count: %d\n", messagesCount)

	bitvectorLen := (messagesCount / 8) + 1
	offset := 2 + bitvectorLen

	fmt.Printf("bitvectorLen = %d, offset = %d\n",
		bitvectorLen, offset)

	revealed := bitvectorToIndexes(bitvector[2:offset])
	fmt.Printf("revealed: %v\n", revealed)

	return messagesCount, offset, revealed
}
