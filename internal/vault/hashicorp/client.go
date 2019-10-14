package hashicorp

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hashicorp/vault/api"
	"log"
	"os"
)

// Environment variable name for Hashicorp Vault authentication credential
const (
	DefaultRoleIDEnv   = "QRM_HASHIVLT_ROLE_ID"
	DefaultSecretIDEnv = "QRM_HASHIVLT_SECRET_ID"
	DefaultTokenEnv    = "QRM_HASHIVLT_TOKEN"
)

type noHashicorpEnvSetErr struct {
	roleIdEnv, secretIdEnv, tokenEnv string
}

func (e noHashicorpEnvSetErr) Error() string {
	return fmt.Sprintf("environment variables are necessary to authenticate with Hashicorp Vault: set %v and %v if using Approle authentication, else set %v", e.roleIdEnv, e.secretIdEnv, e.tokenEnv)
}

type invalidApproleAuthErr struct {
	roleIdEnv, secretIdEnv string
}

func (e invalidApproleAuthErr) Error() string {
	return fmt.Sprintf("both %v and %v environment variables must be set if using Approle authentication", e.roleIdEnv, e.secretIdEnv)
}

type authenticatedClient struct {
	client     *api.Client
	renewer    *api.Renewer
	authConfig VaultAuth
}

func newAuthenticatedClient(vaultAddr string, authConfig VaultAuth, tls TLS) (*authenticatedClient, error) {
	conf := api.DefaultConfig()
	conf.Address = vaultAddr

	tlsConfig := &api.TLSConfig{
		CACert:     tls.CaCert,
		ClientCert: tls.ClientCert,
		ClientKey:  tls.ClientKey,
	}

	if err := conf.ConfigureTLS(tlsConfig); err != nil {
		return nil, fmt.Errorf("error creating Hashicorp client: %v", err)
	}

	c, err := api.NewClient(conf)
	if err != nil {
		return nil, fmt.Errorf("error creating Hashicorp client: %v", err)
	}

	creds, err := getAuthCredentials(authConfig.AuthID)
	if err != nil {
		return nil, err
	}

	if !creds.usingApproleAuth() {
		// authenticate the client with the token provided
		c.SetToken(creds.token)
		return &authenticatedClient{client: c}, nil
	}

	// authenticate the client using approle
	resp, err := approleLogin(c, creds, authConfig.ApprolePath)
	if err != nil {
		return nil, err
	}

	t, err := resp.TokenID()
	if err != nil {
		return nil, err
	}
	c.SetToken(t)

	r, err := c.NewRenewer(&api.RenewerInput{Secret: resp})
	if err != nil {
		return nil, err
	}

	ac := &authenticatedClient{client: c, renewer: r, authConfig: authConfig}
	go ac.renew()

	return ac, nil
}

func approleLogin(c *api.Client, creds authCredentials, approlePath string) (*api.Secret, error) {
	body := map[string]interface{}{"role_id": creds.roleID, "secret_id": creds.secretID}

	approle := approlePath
	if approle == "" {
		approle = "approle"
	}

	return c.Logical().Write(fmt.Sprintf("auth/%s/login", approle), body)
}

type authCredentials struct {
	roleID, secretID, token string
}

func (a authCredentials) usingApproleAuth() bool {
	return a.roleID != "" && a.secretID != ""
}

func getAuthCredentials(authID string) (authCredentials, error) {
	roleIDEnv := applyPrefix(authID, DefaultRoleIDEnv)
	secretIDEnv := applyPrefix(authID, DefaultSecretIDEnv)
	tokenEnv := applyPrefix(authID, DefaultTokenEnv)

	roleID := os.Getenv(roleIDEnv)
	secretID := os.Getenv(secretIDEnv)
	token := os.Getenv(tokenEnv)

	if roleID == "" && secretID == "" && token == "" {
		return authCredentials{}, noHashicorpEnvSetErr{roleIdEnv: roleIDEnv, secretIdEnv: secretIDEnv, tokenEnv: tokenEnv}
	}

	if roleID == "" && secretID != "" || roleID != "" && secretID == "" {
		return authCredentials{}, invalidApproleAuthErr{roleIdEnv: roleIDEnv, secretIdEnv: secretIDEnv}
	}

	return authCredentials{
		roleID:   roleID,
		secretID: secretID,
		token:    token,
	}, nil
}

func (ac *authenticatedClient) renew() {
	go ac.renewer.Renew()

	for {
		select {
		case err := <-ac.renewer.DoneCh():
			// Renewal has stopped either due to an unexpected reason (i.e. some error) or an expected reason
			// (e.g. token TTL exceeded).  Either way we must re-authenticate and get a new token.
			if err != nil {
				log.Println("[DEBUG] renewal of Vault auth token failed, attempting re-authentication: ", err)
			}

			// TODO what to do if re-authentication fails?  wait some time and retry?
			creds, err := getAuthCredentials(ac.authConfig.AuthID)
			if err != nil {
				log.Println("[ERROR] Vault re-authentication failed: ", err)
			}

			// authenticate the client using approle
			resp, err := approleLogin(ac.client, creds, ac.authConfig.ApprolePath)
			if err != nil {
				log.Println("[ERROR] Vault re-authentication failed: ", err)
			}

			t, err := resp.TokenID()
			if err != nil {
				log.Println("[ERROR] Vault re-authentication failed: ", err)
			}
			ac.client.SetToken(t)
			go ac.renewer.Renew()

		case renewal := <-ac.renewer.RenewCh():
			log.Printf("[DEBUG] Successfully renewed Vault auth token: %#v", renewal)
		}
	}
}

func applyPrefix(pre, val string) string {
	if pre == "" {
		return val
	}

	return fmt.Sprintf("%v_%v", pre, val)
}

type vaultClientManager struct {
	clients map[string]*authenticatedClient
}

func newVaultClientManager(config VaultConfig) (*vaultClientManager, error) {
	clients := make(map[string]*authenticatedClient, len(config.Auth))
	for _, auth := range config.Auth {
		client, err := newAuthenticatedClient(config.Addr, auth, config.TLS)
		if err != nil {
			return nil, fmt.Errorf("unable to create client for Vault %v using auth %v: err: %v", config.Addr, auth.AuthID, err)
		}
		clients[auth.AuthID] = client
	}
	return &vaultClientManager{clients: clients}, nil
}

func (ks vaultClientManager) GetKey(addr common.Address, filename string, auth string) (*Key, error) {
	panic("implement me")
}

func (ks vaultClientManager) StoreKey(filename string, k *Key, auth string) error {
	panic("implement me")
}

func (ks vaultClientManager) JoinPath(filename string) string {
	panic("implement me")
}
