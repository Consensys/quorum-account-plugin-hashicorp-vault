package hashicorp

import (
	"encoding/hex"
	"net/url"
	"testing"

	util "github.com/consensys/quorum-go-utils/account"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/stretchr/testify/require"
)

func TestAccountsByURL_HasAccountWithAddress_True(t *testing.T) {
	u1, _ := url.Parse("file:///path/to/acct1")
	addr1 := "2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166"
	f1 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr1,
		},
	}
	a := accountsByURL{
		u1: f1,
	}

	byt, _ := hex.DecodeString("2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166")
	var toFind util.Address
	copy(toFind[:], byt)

	got := a.HasAccountWithAddress(toFind)

	require.True(t, got)
}

func TestAccountsByURL_HasAccountWithAddress_MultipleAccounts_True(t *testing.T) {
	u1, _ := url.Parse("file:///path/to/acct1")
	u2, _ := url.Parse("file:///path/to/acct2")
	addr1 := "2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166"
	addr2 := "dc62574e0f79f5e9585dca30d7161d729496f14e"

	f1 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr1,
		},
	}
	f2 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr2,
		},
	}
	a := accountsByURL{
		u1: f1,
		u2: f2,
	}

	byt, _ := hex.DecodeString("2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166")
	var toFind util.Address
	copy(toFind[:], byt)

	got := a.HasAccountWithAddress(toFind)

	require.True(t, got)
}

func TestAccountsByURL_HasAccountWithAddress_DuplicateAccounts_True(t *testing.T) {
	u1, _ := url.Parse("file:///path/to/acct1")
	u2, _ := url.Parse("file:///path/to/acct1")
	addr1 := "2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166"
	addr2 := "2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166"

	f1 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr1,
		},
	}
	f2 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr2,
		},
	}
	a := accountsByURL{
		u1: f1,
		u2: f2,
	}

	byt, _ := hex.DecodeString("2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166")
	var toFind util.Address
	copy(toFind[:], byt)

	got := a.HasAccountWithAddress(toFind)

	require.True(t, got)
}

func TestAccountsByURL_HasAccountWithAddress_False(t *testing.T) {
	u2, _ := url.Parse("file:///path/to/acct2")
	addr2 := "dc62574e0f79f5e9585dca30d7161d729496f14e"
	f2 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr2,
		},
	}
	a := accountsByURL{
		u2: f2,
	}

	byt, _ := hex.DecodeString("2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166")
	var toFind util.Address
	copy(toFind[:], byt)

	got := a.HasAccountWithAddress(toFind)

	require.False(t, got)
}

func TestAccountsByURL_GetAccountWithAddress(t *testing.T) {
	u1, _ := url.Parse("file:///path/to/acct1")
	addr1 := "2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166"
	f1 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr1,
		},
	}
	a := accountsByURL{
		u1: f1,
	}

	byt, _ := hex.DecodeString("2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166")
	var toFind util.Address
	copy(toFind[:], byt)

	got, err := a.GetAccountWithAddress(toFind)
	require.NoError(t, err)
	require.Equal(t, f1, got)
}

func TestAccountsByURL_GetAccountWithAddress_MultipleAccounts(t *testing.T) {
	u1, _ := url.Parse("file:///path/to/acct1")
	u2, _ := url.Parse("file:///path/to/acct2")
	addr1 := "2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166"
	addr2 := "dc62574e0f79f5e9585dca30d7161d729496f14e"

	f1 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr1,
		},
	}
	f2 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr2,
		},
	}
	a := accountsByURL{
		u1: f1,
		u2: f2,
	}

	byt, _ := hex.DecodeString("2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166")
	var toFind util.Address
	copy(toFind[:], byt)

	got, err := a.GetAccountWithAddress(toFind)
	require.NoError(t, err)
	require.Equal(t, f1, got)
}

func TestAccountsByURL_HasAccountWithAddress_DuplicateAccounts_Error(t *testing.T) {
	u1, _ := url.Parse("file:///path/to/acct1")
	u2, _ := url.Parse("file:///path/to/acct1")
	addr1 := "2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166"
	addr2 := "2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166"

	f1 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr1,
		},
	}
	f2 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr2,
		},
	}
	a := accountsByURL{
		u1: f1,
		u2: f2,
	}

	byt, _ := hex.DecodeString("2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166")
	var toFind util.Address
	copy(toFind[:], byt)

	_, err := a.GetAccountWithAddress(toFind)

	require.EqualError(t, err, ambiguousAccountErr.Error())
}

func TestAccountsByURL_HasAccountWithAddress_NotFound_Error(t *testing.T) {
	u2, _ := url.Parse("file:///path/to/acct2")
	addr2 := "dc62574e0f79f5e9585dca30d7161d729496f14e"
	f2 := config.AccountFile{
		Contents: config.AccountFileJSON{
			Address: addr2,
		},
	}
	a := accountsByURL{
		u2: f2,
	}

	byt, _ := hex.DecodeString("2ea32174140e8f9b24aaf4a066a7dc2dcb6c4166")
	var toFind util.Address
	copy(toFind[:], byt)

	_, err := a.GetAccountWithAddress(toFind)

	require.EqualError(t, err, unknownAccountErr.Error())
}
