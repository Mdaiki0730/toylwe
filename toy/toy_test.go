package toylwe

import "testing"

// KeyGen: B[i] - A[i]・S is a "small error" (-2..2)
func TestKeyGen(t *testing.T) {
	pk, sk := KeyGen()
	allZero := true
	for i := 0; i < M; i++ {
		sum := 0
		for j := 0; j < N; j++ {
			sum += pk.A[i][j] * sk.S[j]
			if pk.A[i][j] != 0 {
				allZero = false
			}
		}
		e := mod(pk.B[i] - sum)
		if e > Q/2 {
			e -= Q
		}
		if e < -ErrBound || e > ErrBound {
			t.Fatalf("row %d: B - A・S = %d. The error is too large (check mod and smallError)", i, e)
		}
	}
	if allZero {
		t.Fatal("A is all 0. Fill it randomly")
	}
}

// Check if 0 and 1 are encrypted and decrypted multiple times, and return to the original
func TestRoundTrip(t *testing.T) {
	for trial := 0; trial < 200; trial++ {
		pk, sk := KeyGen()
		for _, bit := range []int{0, 1} {
			ct := Encrypt(pk, bit)
			if got := Decrypt(sk, ct); got != bit {
				t.Fatalf("trial %d: bit=%d is encrypted, but the decryption result is %d", trial, bit, got)
			}
		}
	}
}

// Check if the same bit results in a different ciphertext each time (if not, it will be revealed to the eavesdropper)
func TestRandomized(t *testing.T) {
	pk, _ := KeyGen()
	if Encrypt(pk, 1) == Encrypt(pk, 1) && Encrypt(pk, 1) == Encrypt(pk, 1) {
		t.Fatal("the same bit's ciphertext is the same each time. Check if the row selection is random")
	}
}

// Check if the ciphertext values are within 0..Q-1
func TestRange(t *testing.T) {
	pk, _ := KeyGen()
	ct := Encrypt(pk, 1)
	if ct.V < 0 || ct.V >= Q {
		t.Fatalf("V=%d is out of range. Did you forget to mod?", ct.V)
	}
	for _, u := range ct.U {
		if u < 0 || u >= Q {
			t.Fatalf("U element %d is out of range", u)
		}
	}
}
