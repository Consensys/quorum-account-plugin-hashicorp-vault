package hashicorp

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"io/ioutil"
	"strconv"
)

// getKey returns the key for the given account.  If the account is locked and allowUnlock is true, the account will be unlocked by retrieving the key from the vault.  zeroFn is the corresponding zero function for the returned key and should be called to clean up once the key has been used.  Calls updateCache before attempting to get the key.
//
// The returned key will first be validated to make sure that it is the correct key for the given address.  If not an error will be returned.
func (w *wallet) getKey(acct accounts.Account, allowUnlock bool) (*ecdsa.PrivateKey, func(), error) {
	if w.isClosed() {
		return nil, func() {}, accounts.ErrWalletClosed
	}

	w.reloadCache()

	w.cache.Mu.Lock()
	a, err := w.cache.Find(acct)
	w.cache.Mu.Unlock()

	if err != nil {
		return nil, func() {}, err
	}

	if u, ok := w.unlocked[a.Address]; ok {
		return u.PrivateKey, func() {}, nil
	}

	if !allowUnlock {
		return nil, func() {}, keystore.ErrLocked
	}

	key, err := w.getKeyUsingFileConfig(a.Address, a.URL.Path)

	if err != nil {
		return nil, func() {}, err
	}

	zeroFn := func() {
		b := key.D.Bits()
		for i := range b {
			b[i] = 0
		}
		key = nil
	}

	return key, zeroFn, err
}

func (w *wallet) getKeyUsingFileConfig(addr common.Address, path string) (*ecdsa.PrivateKey, error) {
	// TODO parity with cache getAddress
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config HashicorpAccountConfig

	if err := json.Unmarshal(fileBytes, &config); err != nil {
		return nil, err
	}

	if config == (HashicorpAccountConfig{}) {
		return nil, fmt.Errorf("unable to read vault account config from file %v", path)
	}

	return w.getKeyFromVault(config)
}

// getKeyFromVault retrieves the private key component of the provided secret from the Vault. Expects RLock to be held.
func (w *wallet) getKeyFromVault(c HashicorpAccountConfig) (*ecdsa.PrivateKey, error) {
	hexKey, err := w.getSecretFromVault(c.SecretPath, c.SecretVersion, c.SecretEnginePath)

	if err != nil {
		return nil, err
	}

	key, err := crypto.HexToECDSA(hexKey)

	if err != nil {
		return nil, fmt.Errorf("unable to parse data from Hashicorp Vault to *ecdsa.PrivateKey: %v", err)
	}

	return key, nil
}

// getSecretFromVault retrieves a particular version of the secret 'name' from the provided secret engine. Expects RLock to be held.
func (w *wallet) getSecretFromVault(name string, version int64, engine string) (string, error) {
	path := fmt.Sprintf("%s/data/%s", engine, name)

	versionData := make(map[string][]string)
	versionData["version"] = []string{strconv.FormatInt(version, 10)}

	resp, err := w.client.Logical().ReadWithData(path, versionData)

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
