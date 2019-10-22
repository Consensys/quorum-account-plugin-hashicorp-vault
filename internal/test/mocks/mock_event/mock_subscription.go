package mock_event

// An no-op stub implementation of the geth event.Subscription interface
type StubSubscription struct{}

func (StubSubscription) Err() <-chan error {
	return nil
}

func (StubSubscription) Unsubscribe() {
	// do nothing
}
