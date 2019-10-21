package hashicorp

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_UnlockAccounts(t *testing.T) {
	err := unlockAccounts(&Backend{}, "")
	require.Error(t, err)
}
