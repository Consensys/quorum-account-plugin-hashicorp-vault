package hashicorp

import (
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
)

func MakeWalletUrl(vaultUrl, authorizationID string) (accounts.URL, error) {
	url, err := vault.ToUrl(vaultUrl)
	if err != nil {
		return accounts.URL{}, err
	}

	wltPath := url.Path

	if authorizationID != "" {
		wltPath = fmt.Sprintf("%v@%v", authorizationID, wltPath)
	}

	return accounts.URL{Scheme: WalletScheme, Path: wltPath}, nil
}
