package hashicorp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

func (w *wallet) NewAccount(config interface{}) (common.Address, error) {
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return common.Address{}, err
	}
	// zero the key as new accounts should be locked by default
	defer vault.ZeroKey(key)

	return w.add(key, config)
}

func (w *wallet) Import(key *ecdsa.PrivateKey, config interface{}) (common.Address, error) {
	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return common.Address{}, err
	}
	// zero the key as new accounts should be locked by default
	defer vault.ZeroKey(key)

	return w.add(key, config)
}

func (w *wallet) add(key *ecdsa.PrivateKey, config interface{}) (common.Address, error) {
	if w.cache.HasAddress(crypto.PubkeyToAddress(key.PublicKey)) {
		return common.Address{}, fmt.Errorf("account already exists")
	}

	c, ok := config.(HashicorpAccountConfig)

	if !ok {
		return common.Address{}, errors.New("config is not of type HashicorpAccountConfig")
	}

	if err := c.ValidateForAccountCreation(); err != nil {
		return common.Address{}, err
	}

	acct, _, err := writeToHashicorpVaultAndFile(w, key, c)

	if err != nil {
		return common.Address{}, err
	}

	// Add the account to the cache immediately rather
	// than waiting for file system notifications to pick it up.
	w.cache.Add(acct)

	return acct.Address, nil
}

// writeSecret stores value in the configured Vault at the location defined by name and secretEngine.
// The secret path and version are returned.
func (w *wallet) writeSecret(config HashicorpAccountConfig, name, value string) (string, int64, error) {
	urlPath := fmt.Sprintf("%s/data/%s", config.SecretEnginePath, config.SecretPath)

	data := make(map[string]interface{})
	data["data"] = map[string]interface{}{
		name: value,
	}

	if !config.SkipCas {
		data["options"] = map[string]interface{}{
			"cas": config.CasValue,
		}
	}

	w.mutex.RLock()
	resp, err := w.client.Logical().Write(urlPath, data)
	w.mutex.RUnlock()

	if err != nil {
		return "", -1, fmt.Errorf("error writing secret to vault: %v", err)
	}

	v, ok := resp.Data["version"]

	if !ok {
		v = json.Number("-1")
	}

	vJson, ok := v.(json.Number)

	version, err := vJson.Int64()

	if err != nil {
		return "", -1, fmt.Errorf("unable to convert version in Vault response to int64: version number is %v", vJson.String())
	}

	return urlPath, version, nil
}

// CreateAccountInHashicorpVault generates a secp256k1 key and corresponding Geth address and stores both in the Vault defined in the provided config.  The key and address are stored in hex string format.
//
// The generated key and address will be saved to only the first HashicorpSecretConfig provided in config.  Any other secret configs are ignored.
//
// The 20-byte hex representation of the Geth address is returned along with the urls of all secrets written to the Vault.  If an error is encountered during the write, the urls of any secrets already written to the vault will be included in the error.
func CreateHashicorpVaultAccount(walletConfig HashicorpWalletConfig, acctConfig HashicorpAccountConfig) (accounts.Account, string, error) {
	w, err := NewHashicorpWallet(walletConfig, &Backend{}, true)
	if err != nil {
		return accounts.Account{}, "", err
	}

	if err := w.Open(""); err != nil {
		return accounts.Account{}, "", err
	}
	defer w.Close()

	if _, err := w.Status(); err != nil {
		return accounts.Account{}, "", err
	}

	key, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return accounts.Account{}, "", err
	}
	defer vault.ZeroKey(key)

	return writeToHashicorpVaultAndFile(w, key, acctConfig)
}

func ImportAsHashicorpVaultAccount(key *ecdsa.PrivateKey, walletConfig HashicorpWalletConfig, acctConfig HashicorpAccountConfig) (accounts.Account, string, error) {
	defer vault.ZeroKey(key)

	w, err := NewHashicorpWallet(walletConfig, &Backend{}, true)
	if err != nil {
		return accounts.Account{}, "", err
	}

	if err := w.Open(""); err != nil {
		return accounts.Account{}, "", err
	}
	defer w.Close()

	if _, err := w.Status(); err != nil {
		return accounts.Account{}, "", err
	}

	return writeToHashicorpVaultAndFile(w, key, acctConfig)
}

// TODO makes sense to have these as functions instead of methods?
// TODO create file first then clean up afterwards if vault write fails
func writeToHashicorpVaultAndFile(w *wallet, key *ecdsa.PrivateKey, acctConfig HashicorpAccountConfig) (accounts.Account, string, error) {
	updatedConfig, err := writeToHashicorpVault(w, key, acctConfig)

	if err != nil {
		return accounts.Account{}, "", err
	}

	path, err := writeToFile(w.config.AccountConfigDir, updatedConfig)

	if err != nil {
		return accounts.Account{}, "", err
	}

	acct := accounts.Account{Address: common.HexToAddress(updatedConfig.Address), URL: accounts.URL{Scheme: keystore.KeyStoreScheme, Path: path}}

	return acct, updatedConfig.secretUrl, nil
}

func writeToHashicorpVault(w *wallet, key *ecdsa.PrivateKey, config HashicorpAccountConfig) (HashicorpAccountConfig, error) {
	address := crypto.PubkeyToAddress(key.PublicKey)
	addrHex := hex.EncodeToString(address[:])

	keyBytes := crypto.FromECDSA(key)
	keyHex := hex.EncodeToString(keyBytes)

	secretBaseUrlPath, secretVersion, err := w.writeSecret(config, addrHex, keyHex)

	if err != nil {
		return HashicorpAccountConfig{}, err
	}

	secretUrlPath := fmt.Sprintf("%v/v1/%v?version=%v", w.client.Address(), secretBaseUrlPath, secretVersion)

	config.SecretVersion = secretVersion
	config.Address = addrHex
	config.secretUrl = secretUrlPath

	return config, nil
}

func writeToFile(dir string, toWrite HashicorpAccountConfig) (string, error) {
	filename := joinPath(
		dir,
		keyFileName(common.HexToAddress(toWrite.Address)),
	)

	configBytes, err := json.Marshal(toWrite)

	if err != nil {
		return "", err
	}

	if err := writeKeyFile(filename, configBytes); err != nil {
		return "", err
	}

	return filename, nil
}

func joinPath(dir, filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	return filepath.Join(dir, filename)
}

// keyFileName implements the naming convention for keyfiles:
// UTC--<created_at UTC ISO8601>-<address hex>
func keyFileName(keyAddr common.Address) string {
	ts := time.Now().UTC()
	return fmt.Sprintf("UTC--%s--%s", toISO8601(ts), hex.EncodeToString(keyAddr[:]))
}

func toISO8601(t time.Time) string {
	var tz string
	name, offset := t.Zone()
	if name == "UTC" {
		tz = "Z"
	} else {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}

func writeKeyFile(file string, content []byte) error {
	name, err := writeTemporaryKeyFile(file, content)
	if err != nil {
		return err
	}
	return os.Rename(name, file)
}

func writeTemporaryKeyFile(file string, content []byte) (string, error) {
	// Create the keystore directory with appropriate permissions
	// in case it is not present yet.
	const dirPerm = 0700
	if err := os.MkdirAll(filepath.Dir(file), dirPerm); err != nil {
		return "", err
	}
	// Atomic write: create a temporary hidden file first
	// then move it into place. TempFile assigns mode 0600.
	f, err := ioutil.TempFile(filepath.Dir(file), "."+filepath.Base(file)+".tmp")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	f.Close()
	return f.Name(), nil
}
