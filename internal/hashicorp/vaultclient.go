package hashicorp

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/jpmorganchase/quorum-plugin-account-store-hashicorp/internal/config"
	"log"
	"time"
)

const reauthRetryInterval = 5 * time.Second

type vaultClient struct {
	*api.Client
	//renewer    *api.Renewer
	//authConfig config.VaultAuth
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
	resp, err := c.authenticateWithApprole(conf)
	if err != nil {
		return err
	}
	return c.startAuthenticationRenewal(resp, conf)
}

func (c *vaultClient) authenticateWithApprole(conf config.VaultClientAuthentication) (*api.Secret, error) {
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

	return resp, nil
}

func (c *vaultClient) startAuthenticationRenewal(resp *api.Secret, conf config.VaultClientAuthentication) error {
	if isRenewable, _ := resp.TokenIsRenewable(); !isRenewable {
		return nil
	}

	r, err := c.NewRenewer(&api.RenewerInput{Secret: resp})
	if err != nil {
		return err
	}

	go c.renew(r, conf)
	return nil
}

// renew starts the client's background process for renewing its auth token.  If the renewal fails, renew will attempt
// reauthentication indefinitely.
func (c *vaultClient) renew(renewer *api.Renewer, conf config.VaultClientAuthentication) {
	go renewer.Renew()

	for {
		select {
		case _ = <-renewer.RenewCh():
			log.Printf("[DEBUG] successfully renewed Vault auth token: approle = %v", conf.ApprolePath)

		case err := <-renewer.DoneCh():
			// Renewal has stopped either due to an unexpected reason (i.e. some error) or an expected reason
			// (e.g. token TTL exceeded).  Either way we must re-authenticate and get a new token.
			switch err {
			case nil:
				log.Printf("[DEBUG] renewal of Vault auth token failed, attempting re-authentication: approle = %v", conf.ApprolePath)
			default:
				log.Printf("[DEBUG] renewal of Vault auth token failed, attempting re-authentication: approle = %v, err = %v", conf.ApprolePath, err)
			}

			for i := 1; ; i++ {
				resp, err := c.authenticateWithApprole(conf)
				if err != nil {
					log.Printf("[ERROR] unable to reauthenticate with Vault (attempt %v): approle = %v, err = %v", i, conf.ApprolePath, err)
					time.Sleep(reauthRetryInterval)
					continue
				}
				log.Printf("[DEBUG] successfully re-authenticated with Vault: approle = %v", conf.ApprolePath)

				if err := c.startAuthenticationRenewal(resp, conf); err != nil {
					log.Printf("[ERROR] unable to start renewal of authentication with Vault: approle = %v, err = %v", conf.ApprolePath, err)
				}
				return
			}
		}
	}
}
