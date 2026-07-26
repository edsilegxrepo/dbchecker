package dbchecker

import (
	"time"
)

// Options specifies configuration parameters for batch database checking.
type Options struct {
	Timeout     time.Duration
	Concurrency int
}

// DefaultOptions returns standard default batch check parameters.
func DefaultOptions() Options {
	return Options{
		Timeout:     10 * time.Second,
		Concurrency: 10,
	}
}

// Option represents a functional option for configuring batch check options.
type Option func(*Options)

// WithTimeout configures the maximum duration per database check operation.
func WithTimeout(d time.Duration) Option {
	return func(o *Options) {
		if d > 0 {
			o.Timeout = d
		}
	}
}

// WithConcurrency configures the maximum number of concurrent database check worker routines.
func WithConcurrency(n int) Option {
	return func(o *Options) {
		if n > 0 {
			o.Concurrency = n
		}
	}
}
