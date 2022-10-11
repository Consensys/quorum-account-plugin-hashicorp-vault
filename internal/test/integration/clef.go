package integration

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type clef struct {
	cmd   *exec.Cmd
	stdio stdioPipes
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
	_, err := io.WriteString(c.stdio.stdinPipe, "ok\n")
	require.NoError(t, err)
}

// y sends y to the cmd's stdin
func (c *clef) y(t *testing.T) {
	_, err := io.WriteString(c.stdio.stdinPipe, "y\n")
	require.NoError(t, err)
}

type clefBuilder struct {
	env  []string
	args []string
}

func (b *clefBuilder) addEnv(key, value string) *clefBuilder {
	b.env = append(b.env, fmt.Sprintf("%v=%v", key, value))
	return b
}

func (b *clefBuilder) stdioUI() *clefBuilder {
	b.args = append(b.args, "--stdio-ui")
	return b
}

func (b *clefBuilder) build(t *testing.T, testout, datadir, pluginsConf string) clef {
	// random, empty, keystore so default keystore is not used
	stdKeystore := fmt.Sprintf("/tmp/acct-plugin-tests/%v", rand.Int())

	_ = os.Mkdir(stdKeystore, os.ModePerm)

	args := b.args
	args = append(args,
		"--auditlog",
		fmt.Sprintf("%v/clefaudit.log", testout),
		"--ipcpath",
		datadir,
		"--keystore",
		stdKeystore,
		"--plugins",
		fmt.Sprintf("file://%v", pluginsConf),
		"--plugins.skipverify",
		"--nousb",
		"--http",
	)

	log.Printf("preparing to start: clef %v", strings.Join(args, " "))

	cmd := exec.Command("clef", args...)

	outfile := fmt.Sprintf("%v/clef.log", testout)
	log.Printf("clef log file: path=%v", outfile)
	out, err := os.Create(outfile)
	require.NoError(t, err)

	var stdioui bool
	for _, arg := range args {
		if arg == "--stdio-ui" {
			stdioui = true
		}
	}

	cmd.Env = b.env

	var stdio stdioPipes

	if stdioui {
		stdinPipe, err := cmd.StdinPipe()
		require.NoError(t, err)
		stdoutPipe, err := cmd.StdoutPipe()
		require.NoError(t, err)
		cmd.Stderr = out

		stdio = stdioPipes{
			stdinPipe:  stdinPipe,
			stdoutPipe: stdoutPipe,
		}
	} else {
		stdinPipe, err := cmd.StdinPipe()
		require.NoError(t, err)
		cmd.Stdout = out
		cmd.Stderr = out

		stdio = stdioPipes{
			stdinPipe: stdinPipe,
		}
	}

	return clef{cmd: cmd, stdio: stdio}
}

type stdioPipes struct {
	stdinPipe  io.WriteCloser
	stdoutPipe io.ReadCloser
}

func waitForClef(t *testing.T, clefIPC string) {
	var (
		attempt     = 0
		maxAttempts = 20
		waitPeriod  = 500 * time.Millisecond
	)

	for {
		attempt++
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
		<-time.After(waitPeriod)
	}
}
