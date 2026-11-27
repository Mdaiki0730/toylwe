// Command decrypt decrypts output.json with the legitimate secret key (Alice's side).
//
//	go run ./ctf/decrypt ctf/output.json ctf/solution/secret.json
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"lwego/ctf"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: go run ./ctf/decrypt <output.json> <secret.json>")
	}
	var ch ctf.Challenge
	if err := readJSON(os.Args[1], &ch); err != nil {
		log.Fatal(err)
	}
	var sk ctf.SecretKey
	if err := readJSON(os.Args[2], &sk); err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(ctf.Decrypt(sk, ch.Ciphertext)))
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
