package protoconv

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/types"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
)

func AcctToProto(acct types.Account) *proto.Account {
	return &proto.Account{
		Address: acct.Address.Bytes(),
		Url:     acct.URL.String(),
	}
}

func ProtoToAcct(acct *proto.Account) (types.Account, error) {
	addr := strings.TrimSpace(common.Bytes2Hex(acct.Address))

	if !common.IsHexAddress(addr) {
		return types.Account{}, fmt.Errorf("invalid hex address: %v", addr)
	}

	u, err := url.Parse(acct.Url)
	if err != nil {
		return types.Account{}, err
	}

	return types.Account{
		Address: common.HexToAddress(addr),
		URL:     u,
	}, nil
}
