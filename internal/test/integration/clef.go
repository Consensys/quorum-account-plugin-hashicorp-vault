package integration

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type clef struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
}

func (c *clef) start(t *testing.T) func() {
	err := c.cmd.Start()
	require.NoError(t, err)

	interrupt := func() {
		err := c.cmd.Process.Signal(os.Interrupt)
		require.NoError(t, err)
	}

	return interrupt
}

// ok sends ok to the cmd's stdin
func (c *clef) ok(t *testing.T) {
	_, err := io.WriteString(c.stdin, "ok\n")
	require.NoError(t, err)
}

// y sends y to the cmd's stdin
func (c *clef) y(t *testing.T) {
	_, err := io.WriteString(c.stdin, "y\n")
	require.NoError(t, err)
}

type clefBuilder struct {
	env []string
}

func (b *clefBuilder) addEnv(key, value string) *clefBuilder {
	b.env = append(b.env, fmt.Sprintf("%v=%v", key, value))
	return b
}

func (b *clefBuilder) build(t *testing.T, testout, datadir, pluginsConf string) clef {
	args := []string{
		"--ipcpath",
		datadir,
		"--plugins",
		fmt.Sprintf("file://%v", pluginsConf),
		"--plugins.skipverify",
	}

	log.Printf("preparing to start: clef %v", strings.Join(args, " "))

	cmd := exec.Command("clef", args...)

	outfile := fmt.Sprintf("%v/clef.out", testout)
	log.Printf("clef log file: path=%v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

	cmd.Stdout = out
	cmd.Stderr = out

	cmd.Env = b.env

	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)

	return clef{cmd: cmd, stdin: stdin}
}

func waitForClef(t *testing.T, clefIPC string) {
	var (
		attempt     = 0
		maxAttempts = 10
		waitPeriod  = time.Second
	)

	for {
		attempt++
		<-time.After(waitPeriod)

		log.Printf("checking Clef IPC server is up: attempt %v/%v", attempt, maxAttempts)

		if _, err := os.Stat(clefIPC); err == nil {
			log.Printf("Clef IPC server is up: attempt %v/%v", attempt, maxAttempts)
			break
		} else if os.IsNotExist(err) {
			log.Printf("Clef IPC server is not up: attempt %v/%v", attempt, maxAttempts)
		} else {
			log.Printf("Clef IPC server is not up: attempt %v/%v, err = %v", attempt, maxAttempts, err)
		}

		if attempt == maxAttempts {
			t.Fatal("Clef IPC server retries exceeded")
		}
	}
}
