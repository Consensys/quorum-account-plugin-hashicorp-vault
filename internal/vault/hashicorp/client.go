package hashicorp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
	"github.com/hashicorp/vault/api"
	"github.com/pborman/uuid"
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
	*api.Client
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
		return &authenticatedClient{Client: c}, nil
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

	ac := &authenticatedClient{Client: c, renewer: r, authConfig: authConfig}

	if renewable, _ := resp.TokenIsRenewable(); renewable {
		go ac.renew()
	}

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

const reauthRetryInterval time.Duration = 5000

func (ac *authenticatedClient) renew() {
	go ac.renewer.Renew()

	for {
		select {
		case err := <-ac.renewer.DoneCh():
			// Renewal has stopped either due to an unexpected reason (i.e. some error) or an expected reason
			// (e.g. token TTL exceeded).  Either way we must re-authenticate and get a new token.
			switch err {
			case nil:
				log.Printf("[DEBUG] renewal of Vault auth token failed, attempting re-authentication: auth = %v", ac.authConfig)
			default:
				log.Printf("[DEBUG] renewal of Vault auth token failed, attempting re-authentication: auth = %v, err = %v", ac.authConfig, err)
			}

			for i := 1; ; i++ {
				err := ac.reauthenticate()
				if err == nil {
					log.Printf("[DEBUG] successfully re-authenticated with Vault: auth = %v", ac.authConfig)
					break
				}
				log.Printf("[ERROR] unable to reauthenticate with Vault (attempt %v): auth = %v, err = %v", i, ac.authConfig, err)
				time.Sleep(reauthRetryInterval * time.Millisecond)
			}
			go ac.renewer.Renew()

		case _ = <-ac.renewer.RenewCh():
			log.Printf("[DEBUG] successfully renewed Vault auth token: auth = %v", ac.authConfig)
		}
	}
}

func (ac *authenticatedClient) reauthenticate() error {
	creds, err := getAuthCredentials(ac.authConfig.AuthID)
	if err != nil {
		return err
	}

	// authenticate the client using approle
	resp, err := approleLogin(ac.Client, creds, ac.authConfig.ApprolePath)
	if err != nil {
		return err
	}

	t, err := resp.TokenID()
	if err != nil {
		return err
	}
	ac.Client.SetToken(t)

	r, err := ac.Client.NewRenewer(&api.RenewerInput{Secret: resp})
	if err != nil {
		return err
	}
	ac.renewer = r

	return nil
}

func applyPrefix(pre, val string) string {
	if pre == "" {
		return val
	}

	return fmt.Sprintf("%v_%v", pre, val)
}

type vaultClientManager struct {
	vaultAddr     string
	acctConfigDir string
	clients       map[string]*authenticatedClient
}

func newVaultClientManager(config VaultConfig) (*vaultClientManager, error) {
	clients := make(map[string]*authenticatedClient, len(config.Auth))
	for _, auth := range config.Auth {
		client, err := newAuthenticatedClient(config.URL, auth, config.TLS)
		if err != nil {
			return nil, fmt.Errorf("unable to create client for Vault %v using auth %v: err: %v", config.URL, auth.AuthID, err)
		}
		clients[auth.AuthID] = client
	}
	return &vaultClientManager{
		vaultAddr:     config.URL,
		acctConfigDir: config.AccountConfigDir,
		clients:       clients,
	}, nil
}

func (m *vaultClientManager) GetKey(addr common.Address, filename string, auth string) (*Key, error) {
	fileBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config AccountConfig
	if err := json.Unmarshal(fileBytes, &config); err != nil {
		return nil, err
	}

	if config == (AccountConfig{}) {
		return nil, fmt.Errorf("unable to read vault account config from file %v", filename)
	}

	hexKey, err := m.getSecretFromVault(config.VaultSecret)
	if err != nil {
		return nil, err
	}

	key, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		return nil, fmt.Errorf("unable to parse data from Hashicorp Vault to *ecdsa.PrivateKey: %v", err)
	}

	return &Key{
		Id:         uuid.UUID(config.Id),
		Address:    crypto.PubkeyToAddress(key.PublicKey),
		PrivateKey: key,
	}, nil
}

// getSecretFromVault retrieves a particular version of the secret 'name' from the provided secret engine. Expects RLock to be held.
func (m *vaultClientManager) getSecretFromVault(vaultAccountConfig VaultSecretConfig) (string, error) {
	client, ok := m.clients[vaultAccountConfig.AuthID]
	if !ok {
		return "", fmt.Errorf("no client configured for Vault %v and authID %v", m.vaultAddr, vaultAccountConfig.AuthID)
	}

	path := fmt.Sprintf("%s/data/%s", vaultAccountConfig.PathParams.SecretEnginePath, vaultAccountConfig.PathParams.SecretPath)

	versionData := make(map[string][]string)
	versionData["version"] = []string{strconv.FormatInt(vaultAccountConfig.PathParams.SecretVersion, 10)}

	resp, err := client.Logical().ReadWithData(path, versionData)
	if err != nil {
		return "", fmt.Errorf("unable to get secret from Hashicorp Vault: %v", err)
	}
	if resp == nil {
		return "", fmt.Errorf("no data for secret in Hashicorp Vault")
	}

	respData, ok := resp.Data["data"].(map[string]interface{})
	if !ok {
		return "", errors.New("Hashicorp Vault response does not contain data")
	}
	if len(respData) != 1 {
		return "", errors.New("only one key/value pair is allowed in each Hashicorp Vault secret")
	}

	// get secret regardless of key in map
	var s interface{}
	for _, d := range respData {
		s = d
	}
	secret, ok := s.(string)
	if !ok {
		return "", errors.New("Hashicorp Vault response data is not in string format")
	}

	return secret, nil
}

func (m vaultClientManager) StoreKey(filename string, vaultConfig VaultSecretConfig, k *Key) (vault.AccountAndWalletUrl, string, error) {
	secretUri, secretVersion, err := m.storeInVault(vaultConfig, k)
	if err != nil {
		return vault.AccountAndWalletUrl{}, "", err
	}

	// include the version of the newly created vault secret in the data written to file
	vaultConfig.PathParams.SecretVersion = secretVersion
	acctConfig := AccountConfig{
		Address:     hex.EncodeToString(k.Address[:]),
		VaultSecret: vaultConfig,
		Id:          k.Id.String(),
		Version:     version,
	}

	if err := m.storeInFile(filename, acctConfig, k); err != nil {
		return vault.AccountAndWalletUrl{}, "", fmt.Errorf("secret written to Vault but unable to write data to file: secret uri: %v, err: %v", secretUri, err)
	}

	acct, err := acctConfig.ParseAccount(m.vaultAddr, filename)
	if err != nil {
		return vault.AccountAndWalletUrl{}, "", fmt.Errorf("secret written to Vault but unable to parse as account: secret uri: %v, err: %v", secretUri, err)
	}

	return acct, secretUri, nil
}

func (m vaultClientManager) storeInVault(vaultConfig VaultSecretConfig, k *Key) (string, int64, error) {
	client, ok := m.clients[vaultConfig.AuthID]
	if !ok {
		return "", 0, fmt.Errorf("no client configured for Vault %v and authID %v", m.vaultAddr, vaultConfig.AuthID)
	}

	path := fmt.Sprintf("%s/data/%s", vaultConfig.PathParams.SecretEnginePath, vaultConfig.PathParams.SecretPath)

	address := k.Address
	addrHex := hex.EncodeToString(address[:])

	keyBytes := crypto.FromECDSA(k.PrivateKey)
	keyHex := hex.EncodeToString(keyBytes)

	data := make(map[string]interface{})
	data["data"] = map[string]interface{}{
		addrHex: keyHex,
	}

	if !vaultConfig.InsecureSkipCas {
		data["options"] = map[string]interface{}{
			"cas": vaultConfig.CasValue,
		}
	}

	resp, err := client.Logical().Write(path, data)
	if err != nil {
		return "", 0, fmt.Errorf("unable to write secret to Vault: %v", err)
	}

	v, ok := resp.Data["version"]
	if !ok {
		secretUri := fmt.Sprintf("%v/v1/%v", client.Address(), path)
		return "", 0, fmt.Errorf("secret written to Vault but unable to get version: secret uri: %v, err %v", secretUri, err)
	}
	vJson, ok := v.(json.Number)
	secretVersion, err := vJson.Int64()
	if err != nil {
		secretUri := fmt.Sprintf("%v/v1/%v", client.Address(), path)
		return "", 0, fmt.Errorf("secret written to Vault but unable to convert version in Vault response to int64: secret: %v, version: %v", secretUri, vJson.String())
	}

	secretUri := fmt.Sprintf("%v/v1/%v?version=%v", client.Address(), path, secretVersion)
	return secretUri, secretVersion, nil
}

func (m vaultClientManager) storeInFile(filename string, acctConfig AccountConfig, k *Key) error {
	toStore, err := json.Marshal(acctConfig)
	if err != nil {
		return err
	}
	// Write into temporary file
	tmpName, err := writeTemporaryKeyFile(filename, toStore)
	if err != nil {
		return err
	}

	return os.Rename(tmpName, filename)
}

func (m vaultClientManager) JoinPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(m.acctConfigDir, filename)
}
