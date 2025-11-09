# Proof Generation Overhead Benchmark

This script measures the overhead of proof generation by executing a single operation/test case twice - once with proof generation enabled and once without. It then logs execution times and computes the proof generation overhead.

## Usage

```bash
./scripts/benchmark_proof_overhead.sh [OPTIONS]
```

## Options

- `-t, --type TYPE`: Operation type (`block` or `epoch`, default: `block`)
- `-o, --operation NAME`: Operation name (default: `attestation`)
- `-c, --case CASE`: Specific test case name (optional, will use first available if not specified)
- `-f, --file FILE`: Output file for results summary (default: stdout)
- `-h, --help`: Show help message

## Detailed Logs

The script saves detailed execution logs for both runs in the `benchmark_logs/` directory:
- `{type}_{operation}_{case}_no_proof.log`: Full output from execution without proof generation
- `{type}_{operation}_{case}_with_proof.log`: Full output from execution with proof generation

These logs contain all compiler output, execution traces, and other diagnostic information.

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

### Benchmark with a specific test case and save results to file
```bash
./scripts/benchmark_proof_overhead.sh -t block -o attestation -c first_valid_attestation -f results.txt
```

### Benchmark block_header operation
```bash
./scripts/benchmark_proof_overhead.sh -t block -o block_header
```

## Output

The script produces output in the following format:

```
=== Results ===
Operation: block attestation
Test case: invalid_correct_attestation_included_after_max_inclusion_slot

Execution time WITHOUT proof generation: 5.3s (5300ms)
Execution time WITH proof generation:    240.7s (240700ms)

Proof generation overhead:     235.4s (235400ms)
Multiplicative overhead:       45.42x

=== Summary ===
Baseline (no proof):  5.3s
With proof:          240.7s
Overhead:            235.4s (45.42x)

=== Detailed Logs ===
Without proof: ./benchmark_logs/block_attestation_invalid_correct_attestation_included_after_max_inclusion_slot_no_proof.log
With proof:    ./benchmark_logs/block_attestation_invalid_correct_attestation_included_after_max_inclusion_slot_with_proof.log
```

## Requirements

- The test data must be downloaded: `make download`
- `cargo` must be available in PATH
- The script should be run from within the host directory or use absolute paths

## Notes

- The script uses `--excluded-cases` to run only on a single test case
- Both runs use the `--release` profile for optimal performance
- The first run (without proof generation) establishes the baseline
- The second run (with proof generation) includes all keygen and proof generation operations
- Execution times are measured using nanosecond-precision timestamps
- **Multiplicative overhead (multiplier)** is calculated as: `With Proof Time / Baseline Time`
  - For example, if baseline is 5s and with proof is 240.7s, the multiplier is 48.14x
  - This is more intuitive than percentage for large overheads (e.g., 4814% becomes 48.14x)
- Detailed execution logs are preserved in the `benchmark_logs/` directory for later analysis
