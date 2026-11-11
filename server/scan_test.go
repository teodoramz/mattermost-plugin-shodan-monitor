package main

import (
	"errors"
	"fmt"
	"testing"
)

func TestPlanBatches(t *testing.T) {
	ips := make([]string, 250)
	for i := range ips {
		ips[i] = fmt.Sprintf("8.8.%d.%d", i/200, i%200)
	}
	credits := []keyCredits{
		{key: "dead", err: errors.New("invalid API key")},
		{key: "a", credits: 120},
		{key: "empty", credits: 0},
		{key: "b", credits: 1000},
	}
	batches := planBatches(credits, ips)

	total := 0
	perKey := map[string]int{}
	seen := map[string]bool{}
	for _, b := range batches {
		if len(b.ips) > scanBatchSize {
			t.Fatalf("batch of %d IPs is bigger than %d", len(b.ips), scanBatchSize)
		}
		for _, ip := range b.ips {
			if seen[ip] {
				t.Fatalf("%s scanned twice", ip)
			}
			seen[ip] = true
		}
		total += len(b.ips)
		perKey[b.key] += len(b.ips)
	}
	if total != 250 || perKey["a"] != 120 || perKey["b"] != 130 || perKey["dead"] != 0 || perKey["empty"] != 0 {
		t.Fatalf("total %d, per key %v", total, perKey)
	}
}
