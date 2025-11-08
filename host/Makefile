TARGET = mainnet.tar.gz
EXTRACT_DIR = mainnet
LOGS_DIR = logs
SUMMARIES_DIR = summaries

DOWNLOAD_SCRIPT = ./subscripts/download_ef_data.sh
PARSE_SCRIPT = ./subscripts/parse_log_to_table.sh
SORT_SCRIPT = ./subscripts/sort_table.sh

BLOCK_OPERATIONS = attestation attester_slashing block_header bls_to_execution_change deposit execution_payload proposer_slashing sync_aggregate voluntary_exit withdrawals
EPOCH_OPERATIONS = justification_and_finalization inactivity_updates rewards_and_penalties registry_updates slashings eth1_data_reset pending_deposits pending_consolidations effective_balance_updates slashings_reset randao_mixes_reset historical_summaries_update participation_flag_updates

.PHONY: all download run clean $(addprefix run-, $(BLOCK_OPERATIONS)) $(addprefix run-epoch-, $(EPOCH_OPERATIONS))

# run-execution_payload (not implemented) and run-withdrawals (incompatible with BeaconState workaround) are excluded
all: download run-attestation run-attester_slashing run-block_header run-bls_to_execution_change run-deposit run-proposer_slashing run-sync_aggregate run-voluntary_exit

download:
	@echo "Running download script..."
	@chmod +x $(DOWNLOAD_SCRIPT)
	@$(DOWNLOAD_SCRIPT)

run:
	@echo "Block operations: make run-<operation>"
	@echo "  $(BLOCK_OPERATIONS)"
	@echo ""
	@echo "Epoch operations: make run-epoch-<operation>"
	@echo "  $(EPOCH_OPERATIONS)"
	@exit 1

$(addprefix run-, $(BLOCK_OPERATIONS)): run-%: $(EXTRACT_DIR)
	@mkdir -p $(LOGS_DIR)
	@mkdir -p $(SUMMARIES_DIR)
	@echo "##################################################"
	@echo "Running benchmarks for block operation: $*..."
	@echo "##################################################"
	@NO_COLOR=1 cargo run --release -- \
			--excluded-cases multi_proposer_index_iterations \
			--excluded-cases random_with_exits_with_duplicates \
			block $* \
			2>&1 | tee $(LOGS_DIR)/execution_$*.log
	@echo "Execution complete for block operation: $*."
	@$(PARSE_SCRIPT) $*
	@$(SORT_SCRIPT) $(SUMMARIES_DIR)/summary_$*.md

$(addprefix run-epoch-, $(EPOCH_OPERATIONS)): run-epoch-%: $(EXTRACT_DIR)
	@mkdir -p $(LOGS_DIR)
	@mkdir -p $(SUMMARIES_DIR)
	@echo "##################################################"
	@echo "Running benchmarks for epoch operation: $*..."
	@echo "##################################################"
	@NO_COLOR=1 cargo run --release -- \
			--excluded-cases multi_proposer_index_iterations \
			--excluded-cases random_with_exits_with_duplicates \
			epoch $* \
			2>&1 | tee $(LOGS_DIR)/execution_epoch_$*.log
	@echo "Execution complete for epoch operation: $*."
	@$(PARSE_SCRIPT) epoch_$*
	@$(SORT_SCRIPT) $(SUMMARIES_DIR)/summary_epoch_$*.md

clean:
	@echo "Cleaning up downloaded/execution files..."
	@rm -f $(TARGET)
	@rm -rf $(EXTRACT_DIR)
	@rm -rf $(LOGS_DIR)
	@echo "Clean up complete."
