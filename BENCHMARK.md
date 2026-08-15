# Benchmarks

## Run

- All collector benchmarks: `go test -bench . -benchmem ./pkg/collector`
- Only incident log benchmarks: `go test -bench 'Log' -benchmem ./pkg/collector`
- Specific benchmark: `go test -bench BenchmarkThrottledLogSameReason -benchmem ./pkg/collector`

## Benchmarks included

- `BenchmarkAlwaysLogSameReason` — always logs every incident with one hot reason
- `BenchmarkThrottledLogSameReason` — current throttled path with one hot reason
- `BenchmarkAlwaysLogManyReasons` — always logs while rotating across several reasons
- `BenchmarkThrottledLogManyReasons` — throttled path while rotating across several reasons
- `BenchmarkThrottledLogWindowForcedEmit` — throttled path with a forced emit every iteration

## Notes

- Logger output is discarded to avoid measuring terminal/file I/O.
- These benchmarks compare log-call cost vs throttle-state/mutex overhead.
- Real production logging to stderr/files will be slower than these numbers.
