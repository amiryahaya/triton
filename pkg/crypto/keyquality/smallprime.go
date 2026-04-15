package keyquality

import (
	"crypto/rsa"
	"fmt"
	"math/big"
)

// smallPrimeMax is the upper bound for trial-division primes. 1229 primes
// ≤ 10000 is enough to catch any catastrophically malformed modulus without
// materially slowing the scan.
const smallPrimeMax = 10000

// smallPrimes holds every prime ≤ smallPrimeMax, computed at package init
// via the Sieve of Eratosthenes. Tiny (1229 entries) and fast (~200µs init).
var smallPrimes = sieveOfEratosthenes(smallPrimeMax)

// sieveOfEratosthenes returns every prime <= n.
func sieveOfEratosthenes(n int) []uint64 {
	if n < 2 {
		return nil
	}
	composite := make([]bool, n+1)
	for i := 2; i*i <= n; i++ {
		if composite[i] {
			continue
		}
		for j := i * i; j <= n; j += i {
			composite[j] = true
		}
	}
	var primes []uint64
	for i := 2; i <= n; i++ {
		if !composite[i] {
			primes = append(primes, uint64(i))
		}
	}
	return primes
}

// smallPrimeCheck trial-divides the modulus by every prime ≤ smallPrimeMax.
// Any hit means the modulus is catastrophically broken (a real RSA modulus
// has exactly two ~N/2-bit prime factors).
func smallPrimeCheck(pub *rsa.PublicKey) (Warning, bool) {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 {
		return Warning{}, false
	}
	mod := new(big.Int)
	for _, p := range smallPrimes {
		divisor := new(big.Int).SetUint64(p)
		// Skip the case where N itself equals a small prime (implausible for a key but possible in crafted tests).
		if pub.N.Cmp(divisor) == 0 {
			continue
		}
		mod.Mod(pub.N, divisor)
		if mod.Sign() == 0 {
			return Warning{
				Code:     CodeSmallPrime,
				Severity: SeverityCritical,
				Message:  fmt.Sprintf("modulus divisible by small prime %d (key is trivially factorable)", p),
			}, true
		}
	}
	return Warning{}, false
}
