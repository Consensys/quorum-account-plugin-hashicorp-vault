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

// testableAccountManagerPluginImpl is a HashicorpVaultAccountManagerPlugin but provides a simple gRPC client implementation for integration testing without needing the geth side
type testableAccountManagerPluginImpl struct {
	HashicorpVaultAccountManagerPlugin
}

func (testableAccountManagerPluginImpl) GRPCClient(ctx context.Context, b *plugin.GRPCBroker, cc *grpc.ClientConn) (interface{}, error) {
	return newInitializerAccountManagerClient(cc)
}

type InitializerAccountManagerClient struct {
	iproto.PluginInitializerClient
	sproto.SignerClient
}

func newInitializerAccountManagerClient(cc *grpc.ClientConn) (interface{}, error) {
	initializerClient := iproto.NewPluginInitializerClient(cc)
	accountManagerClient := sproto.NewSignerClient(cc)

	return InitializerAccountManagerClient{
		PluginInitializerClient: initializerClient,
		SignerClient:            accountManagerClient,
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

const (
	caCert     = "test/data/tls/caRoot.pem"
	clientCert = "test/data/tls/quorum-client-chain.pem"
	clientKey  = "test/data/tls/quorum-client.key"
	serverCert = "test/data/tls/localhost-with-san-chain.pem"
	serverKey  = "test/data/tls/localhost-with-san.key"
)
