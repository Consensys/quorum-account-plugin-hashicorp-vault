package main

//go:generate go run -ldflags "${LD_FLAGS}" $GOFILE

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"runtime"
)

const metadataFile = "plugin-meta.json"

var (
	GitCommit  string
	GitBranch  string
	GitRepo    string
	Version    string
	Executable string
	OutputDir  string
)

func main() {
	meta := make(map[string]interface{})
	meta["name"] = "quorum-plugin-hashicorp-vault-account-manager"
	meta["version"] = Version
	meta["os"] = runtime.GOOS
	meta["arch"] = runtime.GOARCH
	meta["gitCommit"] = GitCommit
	meta["gitBranch"] = GitBranch
	meta["gitRepo"] = GitRepo
	meta["entrypoint"] = Executable
	data, err := json.MarshalIndent(meta, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	if err := ioutil.WriteFile(path.Join(OutputDir, metadataFile), data, 0644); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Wrote", metadataFile)
}
