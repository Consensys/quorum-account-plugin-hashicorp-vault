package protoconv

import (
	"github.com/jpmorganchase/quorum-account-manager-plugin-sdk-go/proto"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/hashicorp"
)

func AcctsToProto(accts []hashicorp.Account) []*proto.Account {
	result := make([]*proto.Account, 0, len(accts))
	for i, acct := range accts {
		result[i] = AcctToProto(acct)
	}
	return result
}

func AcctToProto(acct hashicorp.Account) *proto.Account {
	return &proto.Account{
		Address: acct.Address,
		Url:     acct.Url,
	}
}

func AcctFromProto(acct *proto.Account) hashicorp.Account {
	return hashicorp.Account{
		Address: acct.Address,
		Url:     acct.Url,
	}
}
