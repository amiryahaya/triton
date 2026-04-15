package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/scanner/internal/tpmfs"
)

func TestClassifyEventLog(t *testing.T) {
	cases := []struct {
		name    string
		log     *tpmfs.EventLog
		wantPQC string
	}{
		{
			name:    "SHA-256 only",
			log:     &tpmfs.EventLog{AlgoCounts: map[tpmfs.HashAlgo]int{tpmfs.AlgSHA256: 10}},
			wantPQC: "SAFE",
		},
		{
			name:    "SHA-1 only",
			log:     &tpmfs.EventLog{AlgoCounts: map[tpmfs.HashAlgo]int{tpmfs.AlgSHA1: 10}},
			wantPQC: "UNSAFE",
		},
		{
			name:    "mixed SHA-1 + SHA-256",
			log:     &tpmfs.EventLog{AlgoCounts: map[tpmfs.HashAlgo]int{tpmfs.AlgSHA1: 10, tpmfs.AlgSHA256: 10}},
			wantPQC: "TRANSITIONAL",
		},
		{
			name:    "SHA-384 only",
			log:     &tpmfs.EventLog{AlgoCounts: map[tpmfs.HashAlgo]int{tpmfs.AlgSHA384: 10}},
			wantPQC: "SAFE",
		},
		{
			name:    "empty log",
			log:     &tpmfs.EventLog{AlgoCounts: map[tpmfs.HashAlgo]int{}},
			wantPQC: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyEventLog(c.log)
			if got != c.wantPQC {
				t.Errorf("got %q, want %q", got, c.wantPQC)
			}
		})
	}
}
