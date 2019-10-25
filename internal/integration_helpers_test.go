package internal

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	iproto "github.com/goquorum/quorum-plugin-definitions/initializer/go/proto"
	sproto "github.com/goquorum/quorum-plugin-definitions/signer/go/proto"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/config"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/utils"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// testableSignerPluginImpl is a HashicorpVaultAccountManagerPlugin but provides a simple gRPC client implementation for integration testing without needing the geth side
type testableSignerPluginImpl struct {
	HashicorpVaultAccountManagerPlugin
}

func (testableSignerPluginImpl) GRPCClient(ctx context.Context, b *plugin.GRPCBroker, cc *grpc.ClientConn) (interface{}, error) {
	//return sproto.NewSignerClient(cc), nil
	return newInitializerSignerClient(cc)
}

type InitializerSignerClient struct {
	iproto.PluginInitializerClient
	sproto.SignerClient
}

func newInitializerSignerClient(cc *grpc.ClientConn) (interface{}, error) {
	initializerClient := iproto.NewPluginInitializerClient(cc)
	signerClient := sproto.NewSignerClient(cc)

	return InitializerSignerClient{
		PluginInitializerClient: initializerClient,
		SignerClient:            signerClient,
	}, nil
}

func makeWalletUrl(scheme string, vaultUrl string, acctConfig config.AccountConfig) (accounts.URL, error) {
	url, err := utils.ToUrl(vaultUrl)
	if err != nil {
		return accounts.URL{}, err
	}

	wltPath := fmt.Sprintf(
		"%v/v1/%v/data/%v?version=%v#addr=%v",
		url.Path,
		acctConfig.VaultSecret.PathParams.SecretEnginePath,
		acctConfig.VaultSecret.PathParams.SecretPath,
		acctConfig.VaultSecret.PathParams.SecretVersion,
		acctConfig.Address,
	)

	if authID := acctConfig.VaultSecret.AuthID; authID != "" {
		wltPath = fmt.Sprintf("%v@%v", authID, wltPath)
	}

	return accounts.URL{Scheme: scheme, Path: wltPath}, nil
}
