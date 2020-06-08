package account

import (
	"net/url"
	"testing"

	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
	"github.com/stretchr/testify/require"
)

func TestAccount_ToProtoAccount(t *testing.T) {
	u, _ := url.Parse("scheme://someurl")
	acct := Account{
		Address: Address([20]byte{218, 113, 240, 116, 70, 237, 30, 202, 48, 68, 133, 221, 0, 196, 130, 126, 208, 152, 73, 152}),
		URL:     u,
	}
	got := acct.ToProtoAccount()

	want := &proto.Account{
		Address: []byte{218, 113, 240, 116, 70, 237, 30, 202, 48, 68, 133, 221, 0, 196, 130, 126, 208, 152, 73, 152},
		Url:     "scheme://someurl",
	}

	require.Equal(t, want, got)
}
