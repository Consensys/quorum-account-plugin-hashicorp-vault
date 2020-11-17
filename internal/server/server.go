package server

import (
	"github.com/ConsenSys/quorum-account-plugin-hashicorp-vault/internal/hashicorp"
	"github.com/hashicorp/go-plugin"
)

type HashicorpPlugin struct {
	plugin.Plugin
	acctManager hashicorp.AccountManager
}
