package hashicorp

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/hashicorp/vault/api"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/config"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const reauthRetryInterval = 5 * time.Second

type vaultClient struct {
	*api.Client
	accountDirectory *url.URL
	wallets          map[accounts.URL]config.AccountFile
}

// newVaultClient creates an authenticated Vault client using the credentials provided as environment variables
// (either logging in using the AppRole or using a provided token directly).  Providing tls will configure the client
// to use TLS for Vault communications.  If the AppRole token is renewable the client will be started with a renewer.
func newVaultClient(conf config.VaultClient) (*vaultClient, error) {
	clientConf := api.DefaultConfig()
	clientConf.Address = conf.Vault.String()

	tlsConfig := &api.TLSConfig{
		CACert:     conf.TLS.CaCert.Host + "/" + conf.TLS.CaCert.Path,
		ClientCert: conf.TLS.ClientCert.Host + "/" + conf.TLS.ClientCert.Path,
		ClientKey:  conf.TLS.ClientKey.Host + "/" + conf.TLS.ClientKey.Path,
	}

	if err := clientConf.ConfigureTLS(tlsConfig); err != nil {
		return nil, fmt.Errorf("error creating Hashicorp Vault client: %v", err)
	}

	c, err := api.NewClient(clientConf)
	if err != nil {
		return nil, fmt.Errorf("error creating Hashicorp Vault client: %v", err)
	}

	vaultClient := &vaultClient{Client: c, accountDirectory: conf.AccountDirectory}
	if err := vaultClient.authenticate(conf.Authentication); err != nil {
		return nil, err
	}

	result, err := vaultClient.loadWallets()
	if err != nil {
		return nil, fmt.Errorf("error loading account directory: %v", err)
	}
	vaultClient.wallets = result

	return vaultClient, nil
}

func (c *vaultClient) authenticate(conf config.VaultClientAuthentication) error {
	// authentication config has already been validated so only need to check if approle or token auth is being used
	if conf.Token.IsSet() {
		c.SetToken(conf.Token.Get())
		return nil
	}

	return c.renewableApproleAuthentication(conf)
}

func (c *vaultClient) renewableApproleAuthentication(conf config.VaultClientAuthentication) error {
	renewable, err := c.authenticateWithApprole(conf)
	if err != nil {
		return err
	}
	return renewable.startAuthenticationRenewal(c, conf)
}

func (c *vaultClient) authenticateWithApprole(conf config.VaultClientAuthentication) (*renewable, error) {
	body := map[string]interface{}{"role_id": conf.RoleId.Get(), "secret_id": conf.SecretId.Get()}

	resp, err := c.Logical().Write(fmt.Sprintf("auth/%s/login", conf.ApprolePath), body)
	if err != nil {
		return nil, err
	}

	t, err := resp.TokenID()
	if err != nil {
		return nil, err
	}
	c.SetToken(t)

	return &renewable{Secret: resp}, nil
}

func (c *vaultClient) loadWallets() (map[accounts.URL]config.AccountFile, error) {
	result := make(map[accounts.URL]config.AccountFile)

	walkFn := filepath.WalkFunc(func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// do nothing with directories
			return nil
		}
		b, err := ioutil.ReadFile(path)

		conf := new(config.AccountFileJSON)

		if err := json.Unmarshal(b, conf); err != nil {
			return fmt.Errorf("unable to unmarshal contents of %v, err: %v", path, err)
		}

		acctURL, err := conf.AccountURL(c.Address())
		if err != nil {
			return fmt.Errorf("unable to parse account URL for %v, err %v", path, err)
		}

		result[acctURL] = config.AccountFile{Path: path, Contents: *conf}
		return nil
	})

	if err := filepath.Walk(c.accountDirectory.Host+"/"+c.accountDirectory.Path, walkFn); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *vaultClient) hasWallet(wallet accounts.URL) bool {
	_, hasWallet := c.wallets[wallet]
	return hasWallet
}

func (c *vaultClient) getAccountAddress(wallet accounts.URL) string {
	w, _ := c.wallets[wallet]
	return w.Contents.Address
}
