/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs12381g2pub

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitvector(t *testing.T) {
	bitvector := revealedToBitvector(4, []int{0, 2})

	messagesCount, offset, revealed := bitvectorToRevealed(bitvector)

	require.Equal(t, 4, messagesCount)
	require.Equal(t, 3, offset)
	require.Equal(t, []int{0, 2}, revealed)
}
