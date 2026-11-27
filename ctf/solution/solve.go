// Command solution recovers the flag from output.json without the secret key.
// Implement Attack, then run:
//
//	go run ./ctf/solution ctf/output.json
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"lwego/ctf"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: go run ./ctf/solution <output.json>")
	}
	ch, err := LoadChallenge(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	flag, err := Attack(ch.PublicKey, ch.Ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(flag))
}

// LoadChallenge reads output.json into the challenge's key and ciphertext types.
func LoadChallenge(path string) (ctf.Challenge, error) {
	var ch ctf.Challenge
	data, err := os.ReadFile(path)
	if err != nil {
		return ch, err
	}
	err = json.Unmarshal(data, &ch)
	return ch, err
}

// Attack recovers the plaintext from the public key and ciphertext alone (no secret key).
func Attack(pk ctf.PublicKey, ct ctf.Ciphertext) ([]byte, error) {
	// impl me
	return nil, errors.New("impl me")
}
