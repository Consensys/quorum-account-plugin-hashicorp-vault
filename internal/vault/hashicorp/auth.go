package hashicorp

import (
	"errors"
	"fmt"
	"github.com/hashicorp/vault/api"
	"os"
	"strings"
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

func (w *wallet) setupClient() error {
	conf := api.DefaultConfig()
	conf.Address = w.config.VaultUrl

	tlsConfig := &api.TLSConfig{
		CACert:     w.config.CaCert,
		ClientCert: w.config.ClientCert,
		ClientKey:  w.config.ClientKey,
	}

	if err := conf.ConfigureTLS(tlsConfig); err != nil {
		return fmt.Errorf("error creating Hashicorp client: %v", err)
	}

	c, err := api.NewClient(conf)

	if err != nil {
		return fmt.Errorf("error creating Hashicorp client: %v", err)
	}

	roleIDEnv := applyPrefix(w.config.AuthorizationID, DefaultRoleIDEnv)
	secretIDEnv := applyPrefix(w.config.AuthorizationID, DefaultSecretIDEnv)
	tokenEnv := applyPrefix(w.config.AuthorizationID, DefaultTokenEnv)

	roleID := os.Getenv(roleIDEnv)
	secretID := os.Getenv(secretIDEnv)
	token := os.Getenv(tokenEnv)

	if roleID == "" && secretID == "" && token == "" {
		return noHashicorpEnvSetErr{roleIdEnv: roleIDEnv, secretIdEnv: secretIDEnv, tokenEnv: tokenEnv}
	}

	if roleID == "" && secretID != "" || roleID != "" && secretID == "" {
		return invalidApproleAuthErr{roleIdEnv: roleIDEnv, secretIdEnv: secretIDEnv}
	}

	if usingApproleAuth(roleID, secretID) {
		//authenticate the client using approle
		body := map[string]interface{}{"role_id": roleID, "secret_id": secretID}

		approle := w.config.ApprolePath

		if approle == "" {
			approle = "approle"
		}

		resp, err := c.Logical().Write(fmt.Sprintf("auth/%s/login", approle), body)

		if err != nil {
			switch e := err.(type) {
			case *api.ResponseError:
				ee := errors.New(strings.Join(e.Errors, ","))

				w.failedOpenErr = ee
				return ee
			default:
				w.failedOpenErr = e
				return e
			}
		}

		t, err := resp.TokenID()

		c.SetToken(t)
	} else {
		c.SetToken(token)
	}

	w.mutex.Lock()
	w.client = c
	w.mutex.Unlock()

	return nil
}

func usingApproleAuth(roleID, secretID string) bool {
	return roleID != "" && secretID != ""
}

func applyPrefix(pre, val string) string {
	if pre == "" {
		return val
	}

	return fmt.Sprintf("%v_%v", pre, val)
}
