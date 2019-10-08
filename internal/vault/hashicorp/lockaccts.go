package hashicorp

import (
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/vault"
	"time"
)

// TimedUnlock unlocks the given account for the duration of timeout. A timeout of 0 unlocks the account until the program exits.
//
// If the account address is already unlocked for a duration, TimedUnlock extends or
// shortens the active unlock timeout. If the address was previously unlocked
// indefinitely the timeout is not altered.
//
// If the wallet does not manage this particular account, an error is returned.
func (w *wallet) TimedUnlock(account accounts.Account, timeout time.Duration) error {
	if !w.Contains(account) {
		return accounts.ErrUnknownAccount
	}

	if w.isClosed() {
		return accounts.ErrWalletClosed
	}

	key, _, err := w.getKey(account, true)

	if err != nil {
		return err
	}

	k := &keystore.Key{
		Address:    account.Address,
		PrivateKey: key,
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()
	u, found := w.unlocked[account.Address]
	if found {
		if u.abort == nil {
			// The address was unlocked indefinitely, so unlocking
			// it with a timeout would be confusing.
			return nil
		}
		// Terminate the expire goroutine and replace it below.
		close(u.abort)
	}
	if timeout > 0 {
		u = &unlocked{Key: k, abort: make(chan struct{})}
		go w.expire(account.Address, u, timeout)
	} else {
		u = &unlocked{Key: k}
	}
	w.unlocked[account.Address] = u
	return nil
}

func (w *wallet) expire(addr common.Address, u *unlocked, timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-u.abort:
		// just quit
	case <-t.C:
		w.mutex.Lock()
		// only drop if it's still the same key instance that dropLater
		// was launched with. we can check that using pointer equality
		// because the map stores a new pointer every time the key is
		// unlocked.
		if w.unlocked[addr] == u {
			vault.ZeroKey(u.PrivateKey)
			delete(w.unlocked, addr)
		}
		w.mutex.Unlock()
	}
}

// Lock locks the given account thereby removing the corresponding private key from memory. If the
// wallet does not manage this particular account, an error is returned.
func (w *wallet) Lock(account accounts.Account) error {
	if !w.Contains(account) {
		return accounts.ErrUnknownAccount
	}

	if w.isClosed() {
		return accounts.ErrWalletClosed
	}

	w.mutex.Lock()
	if unl, found := w.unlocked[account.Address]; found {
		w.mutex.Unlock()
		w.expire(account.Address, unl, time.Duration(0)*time.Nanosecond)
	} else {
		w.mutex.Unlock()
	}
	return nil
}
