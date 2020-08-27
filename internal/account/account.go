package account

import (
	util "github.com/consensys/quorum-go-utils/account"
	"github.com/jpmorganchase/quorum-account-plugin-sdk-go/proto"
)

func ToProto(a util.Account) *proto.Account {
	return &proto.Account{
		Address: a.Address.ToBytes(),
		Url:     a.URL.String(),
	}
}
