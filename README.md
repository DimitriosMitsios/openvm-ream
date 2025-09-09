In order to run the project,
```bash
cd host
make download
make run-<OPERATION-NAME>
```
where `OPERATION-NAME = attestation attester_slashing block_header bls_to_execution_change deposit execution_payload proposer_slashing sync_aggregate voluntary_exit withdrawals`

For example, processing an attestation
```bash
cd host
make download
make run-attestation
```

Currently, **no benchmarks** are produced. This functionality will be added soon.