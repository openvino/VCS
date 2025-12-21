#!/usr/bin/env python3
import os
import subprocess
import sys
import tempfile
from pathlib import Path


GO_SNIPPET = r"""
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/arieskmsstore"

	"github.com/trustbloc/kms-go/kms/localkms"
	kmsapi "github.com/trustbloc/kms-go/spi/kms"
	"github.com/trustbloc/kms-go/secretlock/local"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	prefix := os.Getenv("DATABASE_PREFIX")
	masterKey := os.Getenv("VC_REST_LOCAL_KMS_MASTER_KEY")

	if dbURL == "" || prefix == "" || masterKey == "" {
		log.Fatal("missing required env: DATABASE_URL, DATABASE_PREFIX, VC_REST_LOCAL_KMS_MASTER_KEY")
	}

	dbName := prefix + "vcs_db"

	mongoClient, err := mongodb.New(dbURL, dbName)
	if err != nil {
		log.Fatalf("create mongo client: %v", err)
	}

	store := arieskmsstore.NewStore(mongoClient)

	secretLock, err := local.NewService(strings.NewReader(masterKey), nil)
	if err != nil {
		log.Fatalf("create secret lock: %v", err)
	}

	lkms, err := localkms.NewWithOpts(
		localkms.WithPrimaryKeyURI("local-lock://keystorekms"),
		localkms.WithStore(store),
		localkms.WithSecretLock(secretLock),
	)
	if err != nil {
		log.Fatalf("create local kms: %v", err)
	}

	kid, _, err := lkms.Create(kmsapi.AES256GCMNoPrefixType)
	if err != nil {
		log.Fatalf("create key: %v", err)
	}

	fmt.Println(kid)
}
"""


def parse_env_file(env_path: Path) -> dict:
    env = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        env[key.strip()] = val.strip()
    return env


def main():
    repo_root = Path(__file__).resolve().parent
    env_path = repo_root / ".env.local"

    if not env_path.exists():
        print(f"env file not found: {env_path}", file=sys.stderr)
        sys.exit(1)

    env_vars = parse_env_file(env_path)

    required = ["DATABASE_URL", "DATABASE_PREFIX", "VC_REST_LOCAL_KMS_MASTER_KEY"]
    missing = [k for k in required if not env_vars.get(k)]
    if missing:
        print(f"missing required env vars in {env_path}: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    with tempfile.NamedTemporaryFile("w", suffix=".go", dir=repo_root) as f:
        f.write(GO_SNIPPET)
        f.flush()

        run_env = os.environ.copy()
        run_env.update(env_vars)

        result = subprocess.run(
            ["go", "run", f.name],
            cwd=repo_root,
            env=run_env,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
            sys.exit(result.returncode)

        print("Generated VC_REST_DATA_ENCRYPTION_KEY_ID:", result.stdout.strip())


if __name__ == "__main__":
    main()

