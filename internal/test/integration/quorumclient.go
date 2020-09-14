package integration

import (
	"log"
	"testing"
	"time"

	"github.com/consensys/quorum-go-utils/client"
)

// createWSQuorumClient attempts to create a new ws client to a Quorum node.
// If an error is encountered (e.g. the node is still starting), this func will retry a finite number of times.
func createWSQuorumClient(t *testing.T, wsURL string) *client.QuorumClient {
	var (
		c           *client.QuorumClient
		err         error
		maxAttempts = 10
		attempt     = 0
		waitPeriod  = time.Second
	)

	for {
		attempt++
		<-time.After(waitPeriod)

		log.Printf("checking Quorum RPC server is up: attempt %v/%v", attempt, maxAttempts)
		c, err = client.NewQuorumClient(wsURL)
		if err == nil {
			log.Printf("Quorum RPC server is up: attempt %v/%v", attempt, maxAttempts)
			break
		}

		log.Printf("Quorum RPC server is not up: attempt %v/%v", attempt, maxAttempts)
		if attempt == maxAttempts {
			t.Fatal("Quorum RPC server retries exceeded")
		}
	}
	return c
}
