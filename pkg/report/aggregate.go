package report

import (
	"sort"
	"time"

	"github.com/amiryahaya/triton/pkg/model"
)

// MachineSummary holds a per-machine breakdown for aggregate reports.
type MachineSummary struct {
	Hostname      string    `json:"hostname"`
	LatestScanID  string    `json:"latestScanID"`
	LatestScanAt  time.Time `json:"latestScanAt"`
	TotalFindings int       `json:"totalFindings"`
	Safe          int       `json:"safe"`
	Transitional  int       `json:"transitional"`
	Deprecated    int       `json:"deprecated"`
	Unsafe        int       `json:"unsafe"`
	RiskScore     float64   `json:"riskScore"`
}

// AlgorithmUsage tracks how frequently an algorithm appears across machines.
type AlgorithmUsage struct {
	Algorithm    string `json:"algorithm"`
	PQCStatus    string `json:"pqcStatus"`
	MachineCount int    `json:"machineCount"`
	TotalCount   int    `json:"totalCount"`
}

// AggregateReport provides organization-wide posture summary.
type AggregateReport struct {
	GeneratedAt         time.Time        `json:"generatedAt"`
	MachineCount        int              `json:"machineCount"`
	Machines            []MachineSummary `json:"machines"`
	TotalFindings       int              `json:"totalFindings"`
	Safe                int              `json:"safe"`
	Transitional        int              `json:"transitional"`
	Deprecated          int              `json:"deprecated"`
	Unsafe              int              `json:"unsafe"`
	NACSAReadiness      float64          `json:"nacsaReadiness"`
	WorstMachines       []MachineSummary `json:"worstMachines"`
	CommonAlgorithms    []AlgorithmUsage `json:"commonAlgorithms"`
}

// GenerateAggregate computes organization-wide aggregate from multiple scan results.
// Each scan is assumed to be the latest scan for its hostname.
func GenerateAggregate(scans []*model.ScanResult) *AggregateReport {
	agg := &AggregateReport{
		GeneratedAt: time.Now().UTC(),
	}

	// Deduplicate by hostname, keeping latest
	latest := make(map[string]*model.ScanResult)
	for _, s := range scans {
		hostname := s.Metadata.Hostname
		if existing, ok := latest[hostname]; !ok || s.Metadata.Timestamp.After(existing.Metadata.Timestamp) {
			latest[hostname] = s
		}
	}

	agg.MachineCount = len(latest)

	// Track algorithm usage across machines
	algoByMachine := make(map[string]map[string]bool)  // algo -> set of hostnames
	algoCounts := make(map[string]int)                   // algo -> total count
	algoPQC := make(map[string]string)                   // algo -> pqc status

	for hostname, scan := range latest {
		ms := MachineSummary{
			Hostname:      hostname,
			LatestScanID:  scan.ID,
			LatestScanAt:  scan.Metadata.Timestamp,
			TotalFindings: scan.Summary.TotalFindings,
			Safe:          scan.Summary.Safe,
			Transitional:  scan.Summary.Transitional,
			Deprecated:    scan.Summary.Deprecated,
			Unsafe:        scan.Summary.Unsafe,
		}
		// Risk score: weighted sum (unsafe=4, deprecated=3, transitional=1, safe=0)
		ms.RiskScore = float64(ms.Unsafe*4+ms.Deprecated*3+ms.Transitional*1)

		agg.Machines = append(agg.Machines, ms)
		agg.TotalFindings += ms.TotalFindings
		agg.Safe += ms.Safe
		agg.Transitional += ms.Transitional
		agg.Deprecated += ms.Deprecated
		agg.Unsafe += ms.Unsafe

		// Collect algorithm usage
		for _, f := range scan.Findings {
			if f.CryptoAsset == nil {
				continue
			}
			algo := f.CryptoAsset.Algorithm
			algoCounts[algo]++
			algoPQC[algo] = f.CryptoAsset.PQCStatus
			if algoByMachine[algo] == nil {
				algoByMachine[algo] = make(map[string]bool)
			}
			algoByMachine[algo][hostname] = true
		}
	}

	// NACSA readiness: percentage of safe findings
	total := agg.Safe + agg.Transitional + agg.Deprecated + agg.Unsafe
	if total > 0 {
		agg.NACSAReadiness = float64(agg.Safe) / float64(total) * 100
	}

	// Sort machines by hostname for deterministic output
	sort.Slice(agg.Machines, func(i, j int) bool {
		return agg.Machines[i].Hostname < agg.Machines[j].Hostname
	})

	// Worst machines (sorted by risk score descending, top 10)
	worst := make([]MachineSummary, len(agg.Machines))
	copy(worst, agg.Machines)
	sort.Slice(worst, func(i, j int) bool {
		return worst[i].RiskScore > worst[j].RiskScore
	})
	if len(worst) > 10 {
		worst = worst[:10]
	}
	agg.WorstMachines = worst

	// Common algorithms (sorted by total count descending)
	for algo, count := range algoCounts {
		agg.CommonAlgorithms = append(agg.CommonAlgorithms, AlgorithmUsage{
			Algorithm:    algo,
			PQCStatus:    algoPQC[algo],
			MachineCount: len(algoByMachine[algo]),
			TotalCount:   count,
		})
	}
	sort.Slice(agg.CommonAlgorithms, func(i, j int) bool {
		return agg.CommonAlgorithms[i].TotalCount > agg.CommonAlgorithms[j].TotalCount
	})

	return agg
}
