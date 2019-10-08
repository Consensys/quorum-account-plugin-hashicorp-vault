package hashicorp

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"strings"
)

// Status for a hashicorpService
const (
	closed                     = "Closed"
	hashicorpHealthcheckFailed = "Hashicorp Vault healthcheck failed"
	hashicorpUninitialized     = "Hashicorp Vault uninitialized"
	hashicorpSealed            = "Hashicorp Vault sealed"
)

var (
	hashicorpSealedErr        = errors.New(hashicorpSealed)
	hashicorpUninitializedErr = errors.New(hashicorpUninitialized)
)

type hashicorpHealthcheckErr struct {
	err error
}

func (e hashicorpHealthcheckErr) Error() string {
	return fmt.Sprintf("%v: %v", hashicorpHealthcheckFailed, e.err)
}

// Status implements accounts.Wallet, returning a custom status message from the
// underlying vendor-specific vault service implementation.
func (w *wallet) status() (string, error) {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	health, err := w.client.Sys().Health()

	switch {
	case err != nil:
		return w.cacheStatus(), hashicorpHealthcheckErr{err: err}
	case !health.Initialized:
		return w.cacheStatus(), hashicorpUninitializedErr
	case health.Sealed:
		return w.cacheStatus(), hashicorpSealedErr
	}

	return w.cacheStatus(), nil
}

// withAcctStatuses appends the locked/unlocked status of the accounts managed by the service to the provided walletStatus.
// Expects RLock to be held.
func (w *wallet) cacheStatus() string {
	// no accounts so just return
	if w.cache == nil || len(w.cache.All) == 0 {
		return ""
	}

	var (
		unlocked, locked             []string
		unlockedStatus, lockedStatus string
	)

	// TODO this does not account for the case where there are multiple accounts/secret configs for the same address.  If vault url is used as the account url then this doesn't become as much of an issue but the user will be hit with an ambiguous acct error when they attempt to sign even though the status may be unlocked

	for uAddr := range w.unlocked {
		unlocked = append(unlocked, hexutil.Encode(uAddr[:]))
	}

	if len(unlocked) > 0 {
		unlockedStatus = fmt.Sprintf("Unlocked: %v", strings.Join(unlocked, ", "))
	}

	for addr, _ := range w.cache.ByAddr {
		if _, ok := w.unlocked[addr]; !ok {
			locked = append(locked, hexutil.Encode(addr[:]))
		}
	}

	if len(locked) > 0 {
		lockedStatus = fmt.Sprintf("Locked: %v", strings.Join(locked, ", "))
	}

	if unlockedStatus != "" && lockedStatus != "" {
		return fmt.Sprintf("%v; %v", unlockedStatus, lockedStatus)
	} else if unlockedStatus != "" {
		return unlockedStatus
	} else {
		return lockedStatus
	}
}
