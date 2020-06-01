package server

import (
	"github.com/hashicorp/go-plugin"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/hashicorp"
)

type HashicorpPlugin struct {
	plugin.Plugin
	acctManager hashicorp.AccountManager
}
