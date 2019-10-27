// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package manager

import (
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/event"
	"github.com/golang/mock/gomock"
	"github.com/goquorum/quorum-plugin-hashicorp-account-store/internal/test/mocks/mock_cache"
	"github.com/stretchr/testify/require"
)

func TestBackend_Subscribe_StopsUpdatingWhenNoSubscribers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCache := mock_cache.NewMockAccountCache(ctrl)

	b := Backend{
		cache:       mockCache,
		changes:     make(chan struct{}),
		initialised: true,
	}

	mockCache.
		EXPECT().
		Accounts().
		AnyTimes().
		Return([]accounts.Account{})

	var updating bool

	// Ensure that the notification updater is not running yet
	time.Sleep(250 * time.Millisecond)
	b.mu.RLock()
	updating = b.updating
	b.mu.RUnlock()
	require.False(t, updating, "wallet notifier running without subscribers")

	subs := make([]event.Subscription, 2)
	for i := 0; i < len(subs); i++ {
		// Create a new subscription
		subs[i] = b.Subscribe(make(chan<- accounts.WalletEvent))

		// Ensure the notifier comes online
		time.Sleep(250 * time.Millisecond)
		b.mu.RLock()
		updating = b.updating
		b.mu.RUnlock()
		require.True(t, updating, fmt.Sprintf("sub %d: wallet notifier not running after subscription", i))
	}
	// Unsubscribe and ensure the updater terminates eventually
	for i := 0; i < len(subs); i++ {
		// Close an existing subscription
		subs[i].Unsubscribe()

		// Ensure the notifier shuts down at and only at the last close
		for k := 0; k < int(walletRefreshCycle/(250*time.Millisecond))+2; k++ {
			b.mu.RLock()
			updating = b.updating
			b.mu.RUnlock()

			if i < len(subs)-1 && !updating {
				t.Fatalf("sub %d: event notifier stopped prematurely", i)
			}
			if i == len(subs)-1 && !updating {
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	t.Errorf("wallet notifier didn't terminate after unsubscribe")
}
