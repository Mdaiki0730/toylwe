// Package toylwe is a toy LWE cryptosystem based on a "blurred weight scale".
// It sends one bit (0 or 1) per encryption.
package toylwe

import "math/rand/v2"

const (
	Q        = 3329 // the size of the clock (same as in ML-KEM)
	N        = 16   // number of fruits = number of secrets
	M        = 32   // number of lines in the memo opened by the store owner
	ErrBound = 2    // the error of the weight scale is -2 to +2
)

// Memo opened by the store owner. "This combination will result in this blurred total" is M lines.
// B[i] = A[i]・S + e[i]  (mod Q)
type PublicKey struct {
	A [M][N]int // combination
	B [M]int    // blurred total
}

// The true weight of the fruit known only to the store owner.
type SecretKey struct {
	S [N]int // true weight
}

// Bob sends this.
//
//	U = the sum of the combination of the selected row
//	V = the sum of the blurred total of the selected row (+ if you want to send the bit, add half a week's weight)
type Ciphertext struct {
	U [N]int
	V int
}

// mod normalizes to 0..Q-1
func mod(x int) int {
	r := x % Q
	if r < 0 {
		r += Q
	}
	return r
}

// smallError returns a small error in the range -ErrBound..+ErrBound.
func smallError() int {
	return rand.IntN(2*ErrBound+1) - ErrBound
}

// Create a key pair. The store owner determines the true weight and publishes the blurred memo.
func KeyGen() (PublicKey, SecretKey) {
	var pk PublicKey
	var sk SecretKey
	// Fill S[j] with 0..Q-1 random numbers (rand.IntN(Q))
	for i := 0; i < N; i++ {
		sk.S[i] = rand.IntN(Q)
	}
	// Fill A[i][j] with 0..Q-1 random numbers (rand.IntN(Q))
	// sum = Σ_j A[i][j] * S[j]
	// B[i] = mod(sum + smallError())
	for i := 0; i < M; i++ {
		sum := 0
		for j := 0; j < N; j++ {
			pk.A[i][j] = rand.IntN(Q)
			sum += pk.A[i][j] * sk.S[j]
		}
		pk.B[i] = mod(sum + smallError())
	}
	return pk, sk
}

// Encrypt encrypts the bit (0 or 1).
func Encrypt(pk PublicKey, bit int) Ciphertext {
	var ct Ciphertext
	for i := 0; i < M; i++ {
		// For each row i, decide whether to use it (rand.IntN(2))
		if rand.IntN(2) != 1 {
			continue
		}
		// U[j] += A[i][j]   (add the combination)
		for j := 0; j < N; j++ {
			ct.U[j] += pk.A[i][j]
		}
		// V    += B[i]      (add the blurred total)
		ct.V += pk.B[i]
	}
	// If the bit is 1, add Q/2 to V (half a week's weight)
	if bit == 1 {
		ct.V += Q / 2
	}
	// Finally, normalize all of them
	for j := 0; j < N; j++ {
		ct.U[j] = mod(ct.U[j])
	}
	ct.V = mod(ct.V)
	return ct
}

// Decrypt decrypts the bit from the ciphertext.
func Decrypt(sk SecretKey, ct Ciphertext) int {
	realSum := 0
	// Use the secret weight to calculate the "true sum" U・S of the combination U
	for i := 0; i < N; i++ {
		realSum += ct.U[i] * sk.S[i]
	}
	realSum = mod(realSum)
	// w = V - U・S (mod Q)  … this should be a small error or half a week's weight + small error
	w := ct.V - realSum
	w = mod(w)
	// If w is close to 0, return 0, if close to Q/2, return 1
	// (think in terms of the distance on the clock: Q/4 < w < 3Q/4 means 1)
	if w < Q/4 || w > 3*Q/4 {
		return 0
	}
	return 1
}
