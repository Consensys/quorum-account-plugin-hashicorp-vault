package hashicorp

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/account"
	"github.com/jpmorganchase/quorum-account-plugin-hashicorp-vault/internal/config"
)

type AccountManager interface {
	Status() (string, error)
	Accounts() ([]account.Account, error)
	Contains(acctAddr account.Address) bool
	Sign(acctAddr account.Address, toSign []byte) ([]byte, error)
	UnlockAndSign(acctAddr account.Address, toSign []byte) ([]byte, error)
	TimedUnlock(acctAddr account.Address, duration time.Duration) error
	Lock(acctAddr account.Address)
	NewAccount(conf config.NewAccount) (account.Account, error)
	ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (account.Account, error)
}

// NewAccountManager creates a new AccountManager.  The implementation created is determined by the config provided.
func NewAccountManager(config config.VaultClient) (AccountManager, error) {
	if config.KVEngineName != "" {
		return newKVAccountManager(config)
	}
	return newSignerAccountManager(config)
}

func writeAccountFile(path string, data config.AccountFile) error {
	log.Printf("[DEBUG] marshalling file contents: %v", data)
	contents, err := json.Marshal(data.Contents)
	if err != nil {
		return err
	}
	log.Printf("[DEBUG] marshalled file contents: %v", contents)

	log.Printf("[DEBUG] Creating temp file %v/%v", filepath.Dir(path), fmt.Sprintf(".%v*.tmp", filepath.Base(path)))
	f, err := ioutil.TempFile(filepath.Dir(path), fmt.Sprintf(".%v*.tmp", filepath.Base(path)))
	if err != nil {
		return err
	}
	if _, err := f.Write(contents); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	f.Close()

	log.Println("[DEBUG] Renaming temp file")
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return nil
}
