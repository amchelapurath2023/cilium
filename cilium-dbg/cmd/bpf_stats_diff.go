// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var statsFailOnThreshold float64

type bpfProgramStats struct {
	ProgramName  string        `json:"program_name"`
	IfaceName    string        `json:"iface_name,omitempty"`
	PodNamespace string        `json:"pod_namespace,omitempty"`
	PodName      string        `json:"pod_name,omitempty"`
	AvgRuntimeNS time.Duration `json:"avg_runtime_ns"`
}

type diffKey struct {
	ProgramName  string
	PodNamespace string
	PodName      string
	IfaceName    string
}

type byKey []diffKey

func (a byKey) Len() int      { return len(a) }
func (a byKey) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a byKey) Less(i, j int) bool {
	if a[i].ProgramName != a[j].ProgramName {
		return a[i].ProgramName < a[j].ProgramName
	}
	if a[i].PodNamespace != a[j].PodNamespace {
		return a[i].PodNamespace < a[j].PodNamespace
	}
	if a[i].PodName != a[j].PodName {
		return a[i].PodName < a[j].PodName
	}
	return a[i].IfaceName < a[j].IfaceName
}

var bpfStatsDiffCmd = &cobra.Command{
	Use:   "diff <baseline.json> <test.json>",
	Short: "Compare BPF runtime stats against baseline config",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		baselinePath := args[0]
		testPath := args[1]

		baselineRes, err := readStatsReport(baselinePath)
		if err != nil {
			return fmt.Errorf("failed to read baseline file: %w", err)
		}

		testRes, err := readStatsReport(testPath)
		if err != nil {
			return fmt.Errorf("failed to read test file: %w", err)
		}

		baselineStats := aggregateStats(baselineRes)
		testStats := aggregateStats(testRes)

		var keys []diffKey
		for k := range baselineStats {
			keys = append(keys, k)
		}
		for k := range testStats {
			if _, ok := baselineStats[k]; !ok {
				keys = append(keys, k)
			}
		}
		sort.Sort(byKey(keys))

		tw := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

		baselineHeader := strings.ToUpper(strings.TrimSuffix(getFileName(baselinePath), getFileExt(baselinePath)))
		testHeader := strings.ToUpper(strings.TrimSuffix(getFileName(testPath), getFileExt(testPath)))

		fmt.Fprintf(tw, "DEVICE\tPOD\tBPF PROGRAM\t  %s (ns/run)\t  %s (ns/run)\n", baselineHeader, testHeader)

		failed := false
		var failures []string

		for _, k := range keys {
			baseVal, hasBase := baselineStats[k]
			testVal, hasTest := testStats[k]

			baseStr := "-"
			testStr := "-"

			if hasBase {
				baseStr = fmt.Sprintf("%10.2f (   0.00%%)", baseVal)
			}
			if hasTest {
				if hasBase && baseVal > 0 {
					diffPercent := ((testVal - baseVal) / baseVal) * 100.0
					testStr = fmt.Sprintf("%10.2f (%+8.2f%%)", testVal, diffPercent)
					if statsFailOnThreshold >= 0.0 && diffPercent >= statsFailOnThreshold {
						failed = true
						failures = append(failures, fmt.Sprintf("%s (%s/%s, %s) regression: %.2f%% (threshold: %.2f%%)", k.ProgramName, k.PodNamespace, k.PodName, k.IfaceName, diffPercent, statsFailOnThreshold))
					}
				} else {
					testStr = fmt.Sprintf("%10.2f", testVal)
				}
			}

			podStr := ""
			if k.PodName != "" {
				podStr = fmt.Sprintf("%s/%s", k.PodNamespace, k.PodName)
			}

			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", k.IfaceName, podStr, k.ProgramName, baseStr, testStr)
		}
		tw.Flush()

		if failed {
			fmt.Fprintln(os.Stdout, "\nFailure: Performance regression detected!")
			for _, f := range failures {
				fmt.Fprintln(os.Stdout, " -", f)
			}
			return fmt.Errorf("performance regression detected")
		}

		return nil
	},
}

func getFileName(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

func getFileExt(filename string) string {
	parts := strings.Split(filename, ".")
	if len(parts) > 1 {
		return "." + parts[len(parts)-1]
	}
	return ""
}

func readStatsReport(path string) ([]bpfProgramStats, error) {
	bz, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var res []bpfProgramStats
	if err := json.Unmarshal(bz, &res); err != nil {
		return nil, err
	}

	return res, nil
}

func aggregateStats(results []bpfProgramStats) map[diffKey]float64 {
	stats := make(map[diffKey]float64)
	for _, r := range results {
		key := diffKey{
			ProgramName:  r.ProgramName,
			PodNamespace: r.PodNamespace,
			PodName:      r.PodName,
			IfaceName:    r.IfaceName,
		}
		stats[key] = float64(r.AvgRuntimeNS.Nanoseconds())
	}
	return stats
}

func init() {
	BPFStatsCmd.AddCommand(bpfStatsDiffCmd)
	bpfStatsDiffCmd.Flags().Float64Var(&statsFailOnThreshold, "fail-on", -1.0, "Fail if regression percentage is greater than or equal to threshold given")
}
