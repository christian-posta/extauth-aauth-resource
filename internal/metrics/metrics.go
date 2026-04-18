package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	CheckTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aauth_check_total",
		Help: "Total number of AAuth ExtAuthZ checks",
	}, []string{"resource", "level", "result"})

	JwksFetchTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aauth_jwks_fetch_total",
		Help: "Total number of JWKS fetch attempts",
	}, []string{"uri", "result"})

	CheckLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "aauth_check_duration_seconds",
		Help:    "Latency of AAuth checks",
		Buckets: prometheus.DefBuckets,
	}, []string{"resource", "result"})
)
