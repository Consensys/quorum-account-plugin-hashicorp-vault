package hashicorp

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/config"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const reauthRetryInterval = 5 * time.Second

type path string

type vaultClient struct {
	*api.Client
	accounts map[path]config.AccountFileJSON
}

// newVaultClient creates an authenticated Vault client using the credentials provided as environment variables
// (either logging in using the AppRole or using a provided token directly).  Providing tls will configure the client
// to use TLS for Vault communications.  If the AppRole token is renewable the client will be started with a renewer.
func newVaultClient(conf config.VaultClient) (*vaultClient, error) {
	clientConf := api.DefaultConfig()
	clientConf.Address = conf.Vault.String()

	tlsConfig := &api.TLSConfig{
		CACert:     conf.TLS.CaCert.Path,
		ClientCert: conf.TLS.ClientCert.Path,
		ClientKey:  conf.TLS.ClientKey.Path,
	}

	if err := clientConf.ConfigureTLS(tlsConfig); err != nil {
		return nil, fmt.Errorf("error creating Hashicorp Vault client: %v", err)
	}

	c, err := api.NewClient(clientConf)
	if err != nil {
		return nil, fmt.Errorf("error creating Hashicorp Vault client: %v", err)
	}

	vaultClient := &vaultClient{Client: c}
	if err := vaultClient.authenticate(conf.Authentication); err != nil {
		return nil, err
	}

	result, err := vaultClient.loadAccountDirectory(conf.AccountDirectory)
	if err != nil {
		return nil, fmt.Errorf("error loading account directory: %v", err)
	}
	vaultClient.accounts = result

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

func (c *vaultClient) loadAccountDirectory(dir url.URL) (map[path]config.AccountFileJSON, error) {
	result := make(map[path]config.AccountFileJSON)

	walkFn := filepath.WalkFunc(func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// do nothing with directories
			return nil
		}
		b, err := ioutil.ReadFile(dir.Path)

		var conf config.AccountFileJSON

		if err := json.Unmarshal(b, conf); err != nil {
			return fmt.Errorf("unable to unmarshal contents of %v, err: %v", p, err)
		}

		result[path(p)] = conf

		return nil
	})

	if err := filepath.Walk(dir.Path, walkFn); err != nil {
		return nil, err
	}

	return result, nil
}
