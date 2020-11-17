package hashicorp

import (
	"log"
	"time"

	"github.com/ConsenSys/quorum-account-plugin-hashicorp-vault/internal/config"
	"github.com/hashicorp/vault/api"
)

type renewable struct {
	*api.Secret
}

func (r *renewable) startAuthenticationRenewal(client *vaultClient, conf config.VaultClientAuthentication) error {
	if isRenewable, _ := r.TokenIsRenewable(); !isRenewable {
		return nil
	}

	renewer, err := client.NewRenewer(&api.RenewerInput{Secret: r.Secret})
	if err != nil {
		return err
	}

	go r.renewalLoop(renewer, client, conf)
	return nil
}

// renewalLoop starts the background process for renewing the auth token.  If the renewal fails, reauthentication will
// be attempted indefinitely.
func (r *renewable) renewalLoop(renewer *api.Renewer, client *vaultClient, conf config.VaultClientAuthentication) {
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
				renewable, err := client.authenticateWithApprole(conf)
				if err != nil {
					log.Printf("[ERROR] unable to reauthenticate with Vault (attempt %v): approle = %v, err = %v", i, conf.ApprolePath, err)
					time.Sleep(reauthRetryInterval)
					continue
				}
				log.Printf("[DEBUG] successfully re-authenticated with Vault: approle = %v", conf.ApprolePath)

				if err := renewable.startAuthenticationRenewal(client, conf); err != nil {
					log.Printf("[ERROR] unable to start renewal of authentication with Vault: approle = %v, err = %v", conf.ApprolePath, err)
					time.Sleep(reauthRetryInterval)
					continue
				}
				return
			}
		}
	}
}
