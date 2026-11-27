// Package ctf is an 80-bit version of the toy LWE cryptosystem used as a CTF challenge.
// One encryption carries L bits: S is an N x L matrix and V has L slots (Regev multi-bit).
package ctf

import (
	"errors"
	"math/rand/v2"
)

const (
	Q        = 3329 // modulus (same as toy and ML-KEM)
	N        = 48   // secret length (number of fruits)
	M        = 40   // rows in the public memo
	L        = 80   // bits per message = slots in V (10 bytes)
	MsgBytes = L / 8
	ErrBound = 2 // each error is in -ErrBound..+ErrBound
)

// PublicKey is Alice's public memo: B = A·S + E (mod Q).
type PublicKey struct {
	A [M][N]int `json:"A"`
	B [M][L]int `json:"B"`
}

// SecretKey holds one secret column per bit slot.
type SecretKey struct {
	S [N][L]int `json:"S"`
}

// Ciphertext encrypts one L-bit message.
//
//	U = Aᵀ·r,  V = Bᵀ·r + bits·Q/2   (r ∈ {0,1}^M)
type Ciphertext struct {
	U [N]int `json:"U"`
	V [L]int `json:"V"`
}

// Challenge is the file handed to players (output.json).
type Challenge struct {
	PublicKey  PublicKey  `json:"public_key"`
	Ciphertext Ciphertext `json:"ciphertext"`
}

func mod(x int) int {
	r := x % Q
	if r < 0 {
		r += Q
	}
	return r
}

func smallError() int {
	return rand.IntN(2*ErrBound+1) - ErrBound
}

// KeyGen creates Alice's key pair.
func KeyGen() (PublicKey, SecretKey) {
	var pk PublicKey
	var sk SecretKey
	for j := 0; j < N; j++ {
		for k := 0; k < L; k++ {
			sk.S[j][k] = rand.IntN(Q)
		}
	}
	for i := 0; i < M; i++ {
		for j := 0; j < N; j++ {
			pk.A[i][j] = rand.IntN(Q)
		}
		for k := 0; k < L; k++ {
			sum := 0
			for j := 0; j < N; j++ {
				sum += pk.A[i][j] * sk.S[j][k]
			}
			pk.B[i][k] = mod(sum + smallError())
		}
	}
	return pk, sk
}

// ErrTooLong is returned when the message does not fit in L bits.
var ErrTooLong = errors.New("message longer than MsgBytes")

// bit returns bit k of msg, MSB first: slot 8i+0 is the top bit of byte i.
func bit(msg []byte, k int) int {
	return int(msg[k/8]>>(7-k%8)) & 1
}

// Encrypt encrypts up to MsgBytes bytes (zero-padded) into a single ciphertext.
func Encrypt(pk PublicKey, msg []byte) (Ciphertext, error) {
	var ct Ciphertext
	if len(msg) > MsgBytes {
		return ct, ErrTooLong
	}
	padded := make([]byte, MsgBytes)
	copy(padded, msg)
	for i := 0; i < M; i++ {
		if rand.IntN(2) == 0 {
			continue
		}
		for j := 0; j < N; j++ {
			ct.U[j] += pk.A[i][j]
		}
		for k := 0; k < L; k++ {
			ct.V[k] += pk.B[i][k]
		}
	}
	for k := 0; k < L; k++ {
		ct.V[k] += bit(padded, k) * (Q / 2)
	}
	for j := 0; j < N; j++ {
		ct.U[j] = mod(ct.U[j])
	}
	for k := 0; k < L; k++ {
		ct.V[k] = mod(ct.V[k])
	}
	return ct, nil
}

// Decrypt recovers the message with the secret key, dropping zero padding.
func Decrypt(sk SecretKey, ct Ciphertext) []byte {
	bits := make([]int, L)
	for k := 0; k < L; k++ {
		us := 0
		for j := 0; j < N; j++ {
			us += ct.U[j] * sk.S[j][k]
		}
		if w := mod(ct.V[k] - us); w > Q/4 && w < 3*Q/4 {
			bits[k] = 1
		}
	}
	return BitsToBytes(bits)
}

// BitsToBytes packs L bits (MSB first) into bytes and drops trailing zero padding.
func BitsToBytes(bits []int) []byte {
	b := make([]byte, MsgBytes)
	for k, v := range bits {
		b[k/8] |= byte(v) << (7 - k%8)
	}
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}
