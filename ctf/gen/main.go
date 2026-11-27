// Command gen writes the challenge file: the public key and the encrypted flag.
// With -sk it also writes the secret key so ./ctf/decrypt can check the file.
//
//	go run ./ctf/gen -flag 'xxx' -sk ctf/gen/secret.json > ctf/output.json
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"lwego/ctf"
)

func main() {
	f := flag.String("flag", "", "flag to encrypt")
	skPath := flag.String("sk", "", "optional path to write the secret key (JSON)")
	flag.Parse()
	if *f == "" {
		log.Fatal("-flag is required")
	}
	pk, sk := ctf.KeyGen()
	ct, err := ctf.Encrypt(pk, []byte(*f))
	if err != nil {
		log.Fatal(err)
	}
	out := ctf.Challenge{PublicKey: pk, Ciphertext: ct}

	// Sanity check: the legitimate key must decrypt the flag.
	if got := string(ctf.Decrypt(sk, ct)); got != *f {
		log.Fatalf("self-check failed: %q", got)
	}

	if *skPath != "" {
		data, err := json.Marshal(sk)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(*skPath, data, 0o644); err != nil {
			log.Fatal(err)
		}
	}

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		log.Fatal(err)
	}
}
