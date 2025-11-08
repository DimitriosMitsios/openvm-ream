There are two types of tests related to block processing and epoch processing.  

In order to run block operations:

```bash
cd host
make download
make run-<BLOCK-OPERATION-NAME>
```
where `BLOCK-OPERATION-NAME = attestation attester_slashing block_header bls_to_execution_change deposit execution_payload proposer_slashing sync_aggregate voluntary_exit withdrawals`

For example, processing an attestation
```bash
cd host
make download
make run-attestation
```


In order to run epoch processing operations:

```bash
cd host
make download
make run-epoch-<EPOCH-OPERATION-NAME>
```
where `EPOCH-OPERATION-NAME = justification_and_finalization inactivity_updates rewards_and_penalties registry_updates slashings eth1_data_reset pending_deposits pending_consolidations effective_balance_updates slashings_reset randao_mixes_reset historical_summaries_update participation_flag_updates`

For example, processing justification and finalization
```bash
cd host
make download
make run-epoch-justification_and_finalization
```




Currently, **no benchmarks** are produced. This functionality will be added soon.