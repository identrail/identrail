package telemetry

import "github.com/prometheus/client_golang/prometheus"

// Metrics bundles Prometheus instruments used by API and workers.
type Metrics struct {
	ScanRunsTotal                          prometheus.Counter
	ScanEnqueueTotal                       prometheus.Counter
	ScanEnqueueFailureTotal                prometheus.Counter
	ScanEnqueueDurationMS                  prometheus.Histogram
	ScanSuccessTotal                       prometheus.Counter
	ScanFailureTotal                       prometheus.Counter
	ScanPartialTotal                       prometheus.Counter
	ScanInFlight                           prometheus.Gauge
	ScanDurationMS                         prometheus.Histogram
	FindingsGenerated                      prometheus.Counter
	RepoScanRunsTotal                      prometheus.Counter
	RepoScanEnqueueTotal                   prometheus.Counter
	RepoScanEnqueueFailureTotal            prometheus.Counter
	RepoScanEnqueueDurationMS              prometheus.Histogram
	RepoScanSuccessTotal                   prometheus.Counter
	RepoScanFailureTotal                   prometheus.Counter
	RepoScanTruncatedTotal                 prometheus.Counter
	RepoScanDurationMS                     prometheus.Histogram
	ServiceAuthzDenialsTotal               *prometheus.CounterVec
	RepoFindingsGenerated                  prometheus.Counter
	QueueDepth                             *prometheus.GaugeVec
	WorkerJobsTotal                        *prometheus.CounterVec
	WorkerRequeuesTotal                    *prometheus.CounterVec
	WorkerDeadLettersTotal                 *prometheus.CounterVec
	WorkerRetriesTotal                     *prometheus.CounterVec
	AutomationRunsTotal                    *prometheus.CounterVec
	AutomationLagMS                        *prometheus.HistogramVec
	APIDeniedRequestsTotal                 *prometheus.CounterVec
	AuthzPolicyShadowEvaluationsTotal      prometheus.Counter
	AuthzPolicyShadowDivergencesTotal      prometheus.Counter
	AuthzPolicyShadowEvaluationErrorsTotal prometheus.Counter
	AuthzPolicyShadowDivergenceRate        prometheus.Gauge
	AuthzPolicyRollbacksTotal              prometheus.Counter
	AuthzPolicyDecisionsByVersionTotal     *prometheus.CounterVec
}

// NewMetrics initializes a dedicated registry-safe instrument set.
func NewMetrics() *Metrics {
	apiDeniedRequestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "identrail",
		Subsystem: "api",
		Name:      "denied_requests_total",
		Help:      "Total API requests denied by bounded denial kind and source.",
	}, []string{"kind", "source"})

	apiDeniedRequestsTotal.WithLabelValues("unauthorized", "auth")
	apiDeniedRequestsTotal.WithLabelValues("forbidden", "authz")
	apiDeniedRequestsTotal.WithLabelValues("rate_limited", "rate_limit")
	apiDeniedRequestsTotal.WithLabelValues("validation_denied", "validation")

	return &Metrics{
		ScanRunsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "scan",
			Name:      "runs_total",
			Help:      "Total number of scan executions.",
		}),
		ScanEnqueueTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "scan",
			Name:      "enqueue_total",
			Help:      "Total number of scan enqueue requests.",
		}),
		ScanEnqueueFailureTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "scan",
			Name:      "enqueue_failure_total",
			Help:      "Total number of failed scan enqueue requests.",
		}),
		ScanEnqueueDurationMS: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "identrail",
			Subsystem: "scan",
			Name:      "enqueue_duration_milliseconds",
			Help:      "Duration of scan enqueue requests in milliseconds.",
			Buckets:   []float64{10, 25, 50, 100, 250, 500, 1000},
		}),
		ScanSuccessTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "scan",
			Name:      "success_total",
			Help:      "Total number of successful scan runs.",
		}),
		ScanFailureTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "scan",
			Name:      "failure_total",
			Help:      "Total number of failed scan run attempts.",
		}),
		ScanPartialTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "scan",
			Name:      "partial_total",
			Help:      "Total number of scans completed with partial source errors.",
		}),
		ScanInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "identrail",
			Subsystem: "scan",
			Name:      "in_flight",
			Help:      "Current number of in-flight scan triggers.",
		}),
		ScanDurationMS: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "identrail",
			Subsystem: "scan",
			Name:      "duration_milliseconds",
			Help:      "Duration of scans in milliseconds.",
			Buckets:   []float64{100, 250, 500, 1000, 2000, 5000, 10000},
		}),
		FindingsGenerated: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "analysis",
			Name:      "findings_generated_total",
			Help:      "Number of findings generated by the risk engine.",
		}),
		RepoScanRunsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "repo_scan",
			Name:      "runs_total",
			Help:      "Total number of repository exposure scan executions.",
		}),
		RepoScanEnqueueTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "repo_scan",
			Name:      "enqueue_total",
			Help:      "Total number of repository scan enqueue requests.",
		}),
		RepoScanEnqueueFailureTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "repo_scan",
			Name:      "enqueue_failure_total",
			Help:      "Total number of failed repository scan enqueue requests.",
		}),
		RepoScanEnqueueDurationMS: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "identrail",
			Subsystem: "repo_scan",
			Name:      "enqueue_duration_milliseconds",
			Help:      "Duration of repository scan enqueue requests in milliseconds.",
			Buckets:   []float64{10, 25, 50, 100, 250, 500, 1000},
		}),
		RepoScanSuccessTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "repo_scan",
			Name:      "success_total",
			Help:      "Total number of successful repository exposure scans.",
		}),
		RepoScanFailureTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "repo_scan",
			Name:      "failure_total",
			Help:      "Total number of failed repository exposure scans.",
		}),
		RepoScanTruncatedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "repo_scan",
			Name:      "truncated_total",
			Help:      "Total number of repository exposure scans that reached configured scan limits.",
		}),
		RepoScanDurationMS: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "identrail",
			Subsystem: "repo_scan",
			Name:      "duration_milliseconds",
			Help:      "Duration of repository exposure scans in milliseconds.",
			Buckets:   []float64{100, 250, 500, 1000, 2000, 5000, 10000, 30000, 60000},
		}),
		ServiceAuthzDenialsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "authz",
			Name:      "service_denials_total",
			Help:      "Total service-layer authorization denials outside central policy middleware.",
		}, []string{"action", "resource_type"}),
		RepoFindingsGenerated: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "repo_analysis",
			Name:      "findings_generated_total",
			Help:      "Number of findings generated by repository exposure scans.",
		}),
		QueueDepth: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "identrail",
			Subsystem: "queue",
			Name:      "depth",
			Help:      "Current queued job depth by bounded queue name.",
		}, []string{"queue"}),
		WorkerJobsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "worker",
			Name:      "jobs_total",
			Help:      "Total worker queue jobs processed by bounded queue name and outcome.",
		}, []string{"queue", "outcome"}),
		WorkerRequeuesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "worker",
			Name:      "requeues_total",
			Help:      "Total queued jobs requeued by bounded queue name.",
		}, []string{"queue"}),
		WorkerDeadLettersTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "worker",
			Name:      "dead_letters_total",
			Help:      "Total worker jobs or scheduled triggers that exhausted retries by bounded runner name.",
		}, []string{"runner"}),
		WorkerRetriesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "worker",
			Name:      "retries_total",
			Help:      "Total worker retryable failures by bounded runner name.",
		}, []string{"runner"}),
		AutomationRunsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "automation",
			Name:      "runs_total",
			Help:      "Total scheduled, event-driven, and queue automation actions by bounded source, connector, and outcome.",
		}, []string{"source", "connector", "outcome"}),
		AutomationLagMS: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "identrail",
			Subsystem: "automation",
			Name:      "lag_milliseconds",
			Help:      "Observed scheduling or queue lag for automation work by bounded source and queue.",
			Buckets:   []float64{100, 500, 1000, 5000, 15000, 30000, 60000, 300000, 900000, 1800000},
		}, []string{"source", "queue"}),
		APIDeniedRequestsTotal: apiDeniedRequestsTotal,
		AuthzPolicyShadowEvaluationsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "authz_policy_rollout",
			Name:      "shadow_evaluations_total",
			Help:      "Total number of shadow candidate policy evaluations.",
		}),
		AuthzPolicyShadowDivergencesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "authz_policy_rollout",
			Name:      "shadow_divergences_total",
			Help:      "Total number of shadow evaluations where candidate decision diverged from enforced decision.",
		}),
		AuthzPolicyShadowEvaluationErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "authz_policy_rollout",
			Name:      "shadow_evaluation_errors_total",
			Help:      "Total number of shadow candidate evaluations that failed.",
		}),
		AuthzPolicyShadowDivergenceRate: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "identrail",
			Subsystem: "authz_policy_rollout",
			Name:      "shadow_divergence_rate",
			Help:      "Observed shadow divergence rate (divergences/evaluations).",
		}),
		AuthzPolicyRollbacksTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "authz_policy_rollout",
			Name:      "rollbacks_total",
			Help:      "Total number of explicit policy rollback operations.",
		}),
		AuthzPolicyDecisionsByVersionTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "identrail",
			Subsystem: "authz_policy",
			Name:      "decisions_by_version_total",
			Help:      "Total policy decisions grouped by policy version and decision metadata.",
		}, []string{"policy_version", "policy_source", "rollout_mode", "allowed"}),
	}
}
