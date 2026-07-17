// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package metrics

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/prometheus/client_golang/prometheus"

	statstypes "github.com/cilium/cilium/pkg/bpf/stats/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type bpfRuntimeCollector struct {
	logger    *slog.Logger
	collector statstypes.ProgStatsCollector

	bpfProgRunsTotal    *prometheus.Desc
	bpfProgRuntimeTotal *prometheus.Desc
}

func newbpfRuntimeCollector(logger *slog.Logger, collector statstypes.ProgStatsCollector) *bpfRuntimeCollector {
	return &bpfRuntimeCollector{
		logger:    logger,
		collector: collector,
		bpfProgRunsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, SubsystemBPF, "prog_total_runs"),
			"Total executions of a BPF program.",
			[]string{"node", "program_id", "pod_namespace", "pod_name", "device", "name", "type"}, nil,
		),
		bpfProgRuntimeTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, SubsystemBPF, "prog_runtime_total_seconds"),
			"Total execution time of a BPF program in seconds.",
			[]string{"node", "program_id", "pod_namespace", "pod_name", "device", "name", "type"}, nil,
		),
	}
}

func (s *bpfRuntimeCollector) Describe(ch chan<- *prometheus.Desc) {
	if BPFRuntimeStats {
		ch <- s.bpfProgRunsTotal
		ch <- s.bpfProgRuntimeTotal
	}
}

func (s *bpfRuntimeCollector) Collect(ch chan<- prometheus.Metric) {
	if !BPFRuntimeStats {
		return
	}

	nodeName := getLocalNodeName()

	stats, err := s.collector.CollectProgramStats(nil, nil)
	if err != nil {
		s.logger.Error("Failed to query BPF programs", logfields.Error, err)
		return
	}

	for _, info := range stats {
		var device string
		if info.Device != nil {
			device = info.Device.Attrs().Name
		}

		id, _ := info.Info.ID()

		ch <- prometheus.MustNewConstMetric(
			s.bpfProgRunsTotal,
			prometheus.CounterValue,
			float64(info.Stats.RunCount),
			nodeName,
			fmt.Sprintf("%d", id),
			info.Pod.Namespace,
			info.Pod.Name,
			device,
			info.Info.Name,
			info.Info.Type.String(),
		)

		ch <- prometheus.MustNewConstMetric(
			s.bpfProgRuntimeTotal,
			prometheus.CounterValue,
			info.Stats.Runtime.Seconds(),
			nodeName,
			fmt.Sprintf("%d", id),
			info.Pod.Namespace,
			info.Pod.Name,
			device,
			info.Info.Name,
			info.Info.Type.String(),
		)
	}
}

func getLocalNodeName() string {
	if name := os.Getenv("K8S_NODE_NAME"); name != "" {
		return name
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "localhost"
}
