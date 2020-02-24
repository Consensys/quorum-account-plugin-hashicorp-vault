package protoconv

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"strings"
)

func AcctToProto(acct accounts.Account) *proto.Account {
	return &proto.Account{
		Address: acct.Address.Bytes(),
		Url:     acct.URL.String(),
	}
}

func ProtoToAcct(acct *proto.Account) (accounts.Account, error) {
	addr := strings.TrimSpace(common.Bytes2Hex(acct.Address))

	if !common.IsHexAddress(addr) {
		return accounts.Account{}, fmt.Errorf("invalid hex address: %v", addr)
	}

	url := new(accounts.URL)
	if err := json.Unmarshal([]byte(acct.Url), url); err != nil {
		return accounts.Account{}, err
	}

	return accounts.Account{
		Address: common.HexToAddress(addr),
		URL:     *url,
	}, nil
}
