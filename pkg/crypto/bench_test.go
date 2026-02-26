package crypto

import "testing"

// BenchmarkClassifyExact benchmarks exact-match classification (fast path).
func BenchmarkClassifyExact(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ClassifyAlgorithm("AES-256-GCM", 256)
	}
}

// BenchmarkClassifyNormalized benchmarks normalized-match classification.
func BenchmarkClassifyNormalized(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ClassifyAlgorithm("aes_256_gcm", 256)
	}
}

// BenchmarkClassifySubstring benchmarks substring-match classification (slowest path).
func BenchmarkClassifySubstring(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ClassifyAlgorithm("TLS_RSA_WITH_AES_128_CBC_SHA256", 128)
	}
}

// BenchmarkClassifyUnknown benchmarks classification of unknown algorithms.
func BenchmarkClassifyUnknown(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ClassifyAlgorithm("SOME_UNKNOWN_ALGO", 0)
	}
}

// BenchmarkFormatKeySize benchmarks the key size formatting function.
func BenchmarkFormatKeySize(b *testing.B) {
	sizes := []int{0, 128, 256, 2048, 4096}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FormatKeySize(sizes[i%len(sizes)])
	}
}
