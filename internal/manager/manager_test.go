package manager

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_UnlockAccounts(t *testing.T) {
	err := unlockAccounts(&Backend{}, "")
	require.Error(t, err)
}
