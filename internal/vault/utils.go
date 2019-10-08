package vault

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"time"
)

type Unlocker interface {
	TimedUnlock(account accounts.Account, timeout time.Duration) error
}

func ToUrl(strUrl string) (accounts.URL, error) {
	if strUrl == "" {
		return accounts.URL{}, nil
	}

	//to parse a string url as an accounts.URL it must first be in json format
	toParse := fmt.Sprintf("\"%v\"", strUrl)

	var url accounts.URL
	if err := url.UnmarshalJSON([]byte(toParse)); err != nil {
		return accounts.URL{}, err
	}

	return url, nil
}

// accountsByURL implements the sort interface to enable the sorting of a slice of accounts alphanumerically by their urls
type AccountsByURL []accounts.Account

func (s AccountsByURL) Len() int           { return len(s) }
func (s AccountsByURL) Less(i, j int) bool { return s[i].URL.Cmp(s[j].URL) < 0 }
func (s AccountsByURL) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// zeroKey zeroes a private key in memory
func ZeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
