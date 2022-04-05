package hashicorp

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/ConsenSys/quorum-account-plugin-hashicorp-vault/internal/config"
	util "github.com/ConsenSys/quorum-go-utils/account"
)

type AccountManager interface {
	Status() (string, error)
	Accounts() ([]util.Account, error)
	Contains(acctAddr util.Address) bool
	Sign(acctAddr util.Address, toSign []byte) ([]byte, error)
	UnlockAndSign(acctAddr util.Address, toSign []byte) ([]byte, error)
	TimedUnlock(acctAddr util.Address, duration time.Duration) error
	Lock(acctAddr util.Address)
	NewAccount(conf config.NewAccount) (util.Account, error)
	ImportPrivateKey(privateKeyECDSA *ecdsa.PrivateKey, conf config.NewAccount) (util.Account, error)
}

// NewAccountManager creates a new AccountManager.  The implementation created is determined by the config provided.
func NewAccountManager(conf config.VaultClient) (AccountManager, error) {
	if conf.Type() == config.KV {
		return newKVAccountManager(conf)
	}
	return newSignerAccountManager(conf)
}

// writeToFile writes to a temporary hidden file first then renames once complete so that the write appears atomic.  This will be useful if implementing a watcher on the directory
func writeToFile(addrHex string, secretVersion int64, conf config.NewAccount, accountDirectory *url.URL) (config.AccountFile, error) {
	now := time.Now().UTC()
	nowISO8601 := now.Format("2006-01-02T15-04-05.000000000Z")
	filename := fmt.Sprintf("UTC--%v--%v", nowISO8601, addrHex)

	fileURL, err := accountDirectory.Parse(filename)
	if err != nil {
		return config.AccountFile{}, err
	}
	filePath := fileURL.Path
	log.Printf("[DEBUG] writing to file %v", filePath)

	fileData := conf.AccountFile(fileURL.String(), addrHex, secretVersion)

	if err := writeAccountFile(filePath, fileData); err != nil {
		return config.AccountFile{}, err
	}

	return fileData, nil
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
