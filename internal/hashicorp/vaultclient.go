package hashicorp

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/consensys/quorum-account-plugin-hashicorp-vault/internal/config"
	util "github.com/consensys/quorum-go-utils/account"
	"github.com/hashicorp/vault/api"
)

const reauthRetryInterval = 5 * time.Second

type vaultClient struct {
	*api.Client
	secretEngineName string
	readEndpoint     string // the secret engine endpoint used to read/GET accounts - used when constructing the account URL
	accountDirectory *url.URL
	accts            accountsByURL
}

// newVaultClient creates an authenticated Vault client using the credentials provided as environment variables
// (either logging in using the AppRole or using a provided token directly).  Providing tls will configure the client
// to use TLS for Vault communications.  If the AppRole token is renewable the client will be started with a renewer.
func newVaultClient(conf config.VaultClient) (*vaultClient, error) {
	clientConf := api.DefaultConfig()
	clientConf.Address = conf.Vault.String()

	tlsConfig := convertTLSConfig(conf.TLS)

	// passing an empty api.TLSConfig here is equivalent to not adding TLS config
	if err := clientConf.ConfigureTLS(tlsConfig); err != nil {
		return nil, fmt.Errorf("error creating Hashicorp Vault client: %v", err)
	}

	c, err := api.NewClient(clientConf)
	if err != nil {
		return nil, fmt.Errorf("error creating Hashicorp Vault client: %v", err)
	}

	vaultClient := &vaultClient{
		Client:           c,
		secretEngineName: conf.SecretEngineName(),
		readEndpoint:     conf.ReadEndpoint(),
		accountDirectory: conf.AccountDirectory,
	}

	if err := vaultClient.authenticate(conf.Authentication); err != nil {
		return nil, err
	}

	result, err := vaultClient.loadAccounts()
	if err != nil {
		return nil, fmt.Errorf("error loading account directory: %v", err)
	}
	vaultClient.accts = result

	return vaultClient, nil
}

func convertTLSConfig(tls config.VaultClientTLS) *api.TLSConfig {
	tlsConfig := &api.TLSConfig{}

	caCert := tls.CaCert.Host + tls.CaCert.Path
	clientCert := tls.ClientCert.Host + tls.ClientCert.Path
	clientKey := tls.ClientKey.Host + tls.ClientKey.Path

	if caCert != "/" {
		tlsConfig.CACert = caCert
	}
	if clientCert != "/" {
		tlsConfig.ClientCert = clientCert
	}
	if clientKey != "/" {
		tlsConfig.ClientKey = clientKey
	}

	return tlsConfig
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

func (c *vaultClient) loadAccounts() (map[*url.URL]config.AccountFile, error) {
	result := make(map[*url.URL]config.AccountFile)

	walkFn := filepath.WalkFunc(func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// do nothing with directories
			return nil
		}
		log.Printf("[DEBUG] Loading %v", path)
		b, err := ioutil.ReadFile(path)

		conf := new(config.AccountFileJSON)

		if err := json.Unmarshal(b, conf); err != nil {
			return fmt.Errorf("unable to unmarshal contents of %v, err: %v", path, err)
		}

		acctURL, err := conf.AccountURL(c.Address(), c.secretEngineName, c.readEndpoint)
		if err != nil {
			return fmt.Errorf("unable to parse account URL for %v, err: %v", path, err)
		}

		result[acctURL] = config.AccountFile{Path: path, Contents: *conf}
		return nil
	})

	root := c.accountDirectory.Host + "/" + c.accountDirectory.Path

	if _, err := os.Stat(root); os.IsNotExist(err) {
		log.Printf("[DEBUG] Creating empty directory at %v", root)
		if err := os.Mkdir(root, os.ModeDir+0755); err != nil {
			return nil, err
		}
		return result, nil
	}

	log.Printf("[DEBUG] Loading accts from %v", root)
	if err := filepath.Walk(root, walkFn); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *vaultClient) hasAccount(acctAddr util.Address) bool {
	return c.accts.HasAccountWithAddress(acctAddr)
}

func (c *vaultClient) getAccountFile(acctAddr util.Address) (config.AccountFile, error) {
	return c.accts.GetAccountWithAddress(acctAddr)
}

func (c *vaultClient) getAccounts() ([]util.Account, error) {
	var (
		w     = c.accts
		accts = make([]util.Account, 0, len(w))
		acct  util.Account
	)
	for url, conf := range w {
		addr, err := util.NewAddressFromHexString(conf.Contents.Address)
		if err != nil {
			return []util.Account{}, err
		}
		acct = util.Account{
			Address: addr,
			URL:     url,
		}
		accts = append(accts, acct)
	}
	return accts, nil
}
