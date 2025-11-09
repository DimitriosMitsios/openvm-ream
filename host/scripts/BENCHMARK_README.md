# Proof Generation Overhead Benchmark

This script measures the overhead of proof generation by executing a single operation/test case twice - once with proof generation enabled and once without. It then logs execution times and computes the proof generation overhead.

## Usage

```bash
./scripts/benchmark_proof_overhead.sh [OPTIONS]
```

## Options

- `-t, --type TYPE`: Operation type (`block` or `epoch`, default: `block`)
- `-o, --operation NAME`: Operation name (default: `attestation`)
- `-k, --fork FORK`: Ethereum fork version (`electra`, `fulu`, `phase0`, etc., default: `electra`)
- `-f, --file FILE`: Output file for results summary (default: stdout)
- `-h, --help`: Show help message

## Detailed Logs

The script saves detailed execution logs for both runs in the `benchmark_logs/` directory:
- `{type}_{operation}_no_proof.log`: Full output from execution without proof generation (all test cases)
- `{type}_{operation}_with_proof.log`: Full output from execution with proof generation (all test cases)

These logs contain all compiler output, execution traces, and other diagnostic information for all available test cases.

## Block Operations

The following block operations are available:
- attestation
- attester_slashing
- block_header
- bls_to_execution_change
- deposit
- execution_payload
- proposer_slashing
- sync_aggregate
- voluntary_exit
- withdrawals

## Epoch Operations

The following epoch operations are available:
- justification_and_finalization
- inactivity_updates
- rewards_and_penalties
- registry_updates
- slashings
- eth1_data_reset
- pending_deposits
- pending_consolidations
- effective_balance_updates
- slashings_reset
- randao_mixes_reset
- historical_summaries_update
- participation_flag_updates

## Examples

### Basic usage (uses default block attestation)
```bash
./scripts/benchmark_proof_overhead.sh
```

### Benchmark a specific epoch operation
```bash
./scripts/benchmark_proof_overhead.sh -t epoch -o justification_and_finalization
```

### Benchmark with output file
```bash
./scripts/benchmark_proof_overhead.sh -t block -o attestation -f results.txt
```

### Benchmark on different fork (e.g., fulu)
```bash
./scripts/benchmark_proof_overhead.sh -t block -o block_header -k fulu
```

## Output

The script produces output in the following format:

```
=== Proof Generation Overhead Benchmark ===
Operation: block attestation
Fork: electra
Running all available test cases...

[1/2] Running WITHOUT proof generation...
✓ Completed in 489.2s
Detailed log saved to: ./benchmark_logs/block_attestation_no_proof.log

[2/2] Running WITH proof generation...
✓ Completed in 5234.8s
Detailed log saved to: ./benchmark_logs/block_attestation_with_proof.log

=== Results ===
Operation: block attestation
Fork: electra

Execution time WITHOUT proof generation: 489.2s (489200ms)
Execution time WITH proof generation:    5234.8s (5234800ms)

Proof generation overhead:     4745.6s (4745600ms)
Multiplicative overhead:       10.70x

=== Summary ===
Baseline (no proof):  489.2s
With proof:          5234.8s
Overhead:            4745.6s (10.70x)

=== Detailed Logs ===
Without proof: ./benchmark_logs/block_attestation_no_proof.log
With proof:    ./benchmark_logs/block_attestation_with_proof.log
```

## Requirements

- The test data must be downloaded: `make download`
- `cargo` must be available in PATH
- The script should be run from within the host directory or use absolute paths

## Notes

- The script runs **all available test cases** for the specified operation and fork
- Both runs use the `--release` profile for optimal performance
- The first run (without proof generation) establishes the baseline
- The second run (with proof generation) includes all keygen and proof generation operations
- Execution times are measured using nanosecond-precision timestamps
- **Multiplicative overhead (multiplier)** is calculated as: `With Proof Time / Baseline Time`
  - For example, if baseline is 489.2s and with proof is 5234.8s, the multiplier is 10.70x
  - This is more intuitive than percentage for large overheads
- Detailed execution logs are preserved in the `benchmark_logs/` directory for later analysis of individual test cases
