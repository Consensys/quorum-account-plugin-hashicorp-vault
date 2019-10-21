// Package plugintest provides utilities for signer plugin testing
package plugintest

// An no-op stub implementation of the geth event.Subscription interface
type StubSubscription struct{}

func (StubSubscription) Err() <-chan error {
	return nil
}

func (StubSubscription) Unsubscribe() {
	// do nothing
}
