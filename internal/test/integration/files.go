package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testDirName = strconv.FormatInt(time.Now().UnixNano(), 10)

type dirs struct {
	testout string
	datadir string
}

func prepareDirs(t *testing.T, suiteName string, testName string) dirs {
	wd, err := os.Getwd()
	require.NoError(t, err)

	testoutRoot := fmt.Sprintf("%v/testout", wd)
	if _, err := os.Stat(testoutRoot); os.IsNotExist(err) {
		log.Printf("creating testout root dir: path=%v", testoutRoot)
		err = os.Mkdir(testoutRoot, 0700)
		require.NoError(t, err)
	} else {
		log.Printf("testout root dir already exists: path=%v", testoutRoot)
	}

	testout := fmt.Sprintf("%v/%v", testoutRoot, suiteName)
	if _, err := os.Stat(testout); os.IsNotExist(err) {
		log.Printf("creating testout dir: path=%v", testout)
		err = os.Mkdir(testout, 0700)
		require.NoError(t, err)
	} else {
		log.Printf("testout dir already exists: path=%v", testout)
	}

	currentTestout := fmt.Sprintf("%v/%v", testout, testName)
	log.Printf("creating currentTestout dir: path=%v", currentTestout)
	err = os.Mkdir(currentTestout, 0700)
	require.NoError(t, err)

	hash := sha256.Sum256([]byte(testName))

	// we have to hash the testName when creating the dataDir as IPC paths cannot exceed 104 chars
	datadir := fmt.Sprintf("/tmp/datadir/%v/%v", suiteName, hex.EncodeToString(hash[:20]))
	log.Printf("using quorum datadir: path=%v", datadir)

	return dirs{
		testout: currentTestout,
		datadir: datadir,
	}
}

func findFile(targetDir string, pattern string) ([]string, error) {
	return filepath.Glob(fmt.Sprintf("%v/%v", targetDir, pattern))
}
