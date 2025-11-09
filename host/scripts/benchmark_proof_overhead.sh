#!/bin/bash

# Benchmark script to measure proof generation overhead
# Executes a single operation/test case twice: once with proof generation and once without
# Logs execution time for both cases and computes the overhead

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
OPERATION_TYPE="block"
OPERATION_NAME="attestation"
FORK="electra"
TEST_CASE=""
OUTPUT_FILE=""
LOGS_DIR="./benchmark_logs"

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE          Operation type: 'block' or 'epoch' (default: block)"
    echo "  -o, --operation NAME     Operation name (default: attestation)"
    echo "                           Block ops: attestation, attester_slashing, block_header, etc."
    echo "                           Epoch ops: justification_and_finalization, inactivity_updates, etc."
    echo "  -k, --fork FORK          Ethereum fork: 'electra', 'fulu', 'phase0', etc. (default: electra)"
    echo "  -c, --case CASE          Specific test case name (optional, will use first test case if not provided)"
    echo "  -f, --file FILE          Output file for results (default: stdout)"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -t block -o attestation"
    echo "  $0 -t epoch -o justification_and_finalization -f results.txt"
    echo "  $0 --type block --operation block_header --fork fulu --case correct_attestation_included_at_min_inclusion_delay"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            OPERATION_TYPE="$2"
            shift 2
            ;;
        -o|--operation)
            OPERATION_NAME="$2"
            shift 2
            ;;
        -k|--fork)
            FORK="$2"
            shift 2
            ;;
        -c|--case)
            TEST_CASE="$2"
            shift 2
            ;;
        -f|--file)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}=== Proof Generation Overhead Benchmark ===${NC}"
echo -e "${BLUE}Operation: ${OPERATION_TYPE} ${OPERATION_NAME} (fork: ${FORK})${NC}"

# Create logs directory
mkdir -p "$LOGS_DIR"

# Prepare output file if specified
if [[ -n "$OUTPUT_FILE" ]]; then
    exec 1> >(tee "$OUTPUT_FILE")
    exec 2>&1
fi

# Determine the test cases directory structure:
# For block operations: mainnet/tests/mainnet/{fork}/operations/{operation_name}/pyspec_tests/
# For epoch operations: mainnet/tests/mainnet/{fork}/epoch_processing/{operation_name}/pyspec_tests/
TEST_CASES_DIR="$HOST_DIR/mainnet/tests/mainnet"

if [[ "$OPERATION_TYPE" == "block" ]]; then
    OPERATION_CATEGORY="operations"
elif [[ "$OPERATION_TYPE" == "epoch" ]]; then
    OPERATION_CATEGORY="epoch_processing"
else
    echo -e "${YELLOW}Error: Invalid operation type '$OPERATION_TYPE'. Must be 'block' or 'epoch'${NC}"
    exit 1
fi

OPERATION_DIR="$TEST_CASES_DIR/$FORK/$OPERATION_CATEGORY/$OPERATION_NAME/pyspec_tests"

if [[ ! -d "$OPERATION_DIR" ]]; then
    echo -e "${YELLOW}Error: Operation directory not found: $OPERATION_DIR${NC}"
    echo "Make sure you have downloaded the test data with 'make download'"
    echo ""
    echo "Available forks:"
    ls "$TEST_CASES_DIR" 2>/dev/null | head -10
    exit 1
fi

# Get test cases
AVAILABLE_CASES=$(ls "$OPERATION_DIR" | head -5)
if [[ -z "$AVAILABLE_CASES" ]]; then
    echo -e "${YELLOW}Error: No test cases found in $OPERATION_DIR${NC}"
    exit 1
fi

# Use provided test case or get the first available one
if [[ -z "$TEST_CASE" ]]; then
    TEST_CASE=$(echo "$AVAILABLE_CASES" | head -1)
    echo -e "${YELLOW}No specific test case provided, using first available: $TEST_CASE${NC}"
else
    # Verify the test case exists
    if [[ ! -d "$OPERATION_DIR/$TEST_CASE" ]]; then
        echo -e "${YELLOW}Error: Test case '$TEST_CASE' not found${NC}"
        echo "Available test cases:"
        ls "$OPERATION_DIR" | head -10
        exit 1
    fi
fi

echo -e "${BLUE}Test case: ${TEST_CASE}${NC}"
echo ""

# Function to format milliseconds as seconds
format_time() {
    local ms=$1
    echo "$((ms / 1000)).$((ms % 1000 / 100))s"
}

# Function to calculate multiplicative overhead (multiplier)
calculate_multiplier() {
    local with_proof=$1
    local without_proof=$2
    if [ "$without_proof" -eq 0 ]; then
        echo "0"
    else
        # Calculate as float: with_proof / without_proof
        # Using awk for floating point arithmetic
        echo "$(awk "BEGIN {printf \"%.2f\", $with_proof / $without_proof}")"
    fi
}

# Run 1: WITHOUT proof generation
echo -e "${GREEN}[1/2] Running WITHOUT proof generation...${NC}"
START_TIME=$(date +%s%N)
NO_PROOF_LOG="$LOGS_DIR/${OPERATION_TYPE}_${OPERATION_NAME}_${TEST_CASE}_no_proof.log"
cd "$HOST_DIR"
if NO_COLOR=1 cargo run --release -- \
    --fork "$FORK" \
    --excluded-cases "$TEST_CASE" \
    "$OPERATION_TYPE" "$OPERATION_NAME" \
    > "$NO_PROOF_LOG" 2>&1; then
    END_TIME=$(date +%s%N)
    NO_PROOF_TIME=$((($END_TIME - $START_TIME) / 1000000)) # Convert to milliseconds
    NO_PROOF_TIME_SEC=$(format_time "$NO_PROOF_TIME")
    echo -e "${GREEN}✓ Completed in ${NO_PROOF_TIME_SEC}${NC}"
    echo -e "${BLUE}Detailed log saved to: $NO_PROOF_LOG${NC}"
else
    echo -e "${YELLOW}✗ Failed to run without proof generation${NC}"
    cat "$NO_PROOF_LOG"
    exit 1
fi

echo ""

# Run 2: WITH proof generation
echo -e "${GREEN}[2/2] Running WITH proof generation...${NC}"
START_TIME=$(date +%s%N)
WITH_PROOF_LOG="$LOGS_DIR/${OPERATION_TYPE}_${OPERATION_NAME}_${TEST_CASE}_with_proof.log"
cd "$HOST_DIR"
if NO_COLOR=1 cargo run --release -- \
    --fork "$FORK" \
    --excluded-cases "$TEST_CASE" \
    --generate-proof \
    "$OPERATION_TYPE" "$OPERATION_NAME" \
    > "$WITH_PROOF_LOG" 2>&1; then
    END_TIME=$(date +%s%N)
    WITH_PROOF_TIME=$((($END_TIME - $START_TIME) / 1000000)) # Convert to milliseconds
    WITH_PROOF_TIME_SEC=$(format_time "$WITH_PROOF_TIME")
    echo -e "${GREEN}✓ Completed in ${WITH_PROOF_TIME_SEC}${NC}"
    echo -e "${BLUE}Detailed log saved to: $WITH_PROOF_LOG${NC}"
else
    echo -e "${YELLOW}✗ Failed to run with proof generation${NC}"
    cat "$WITH_PROOF_LOG"
    exit 1
fi

echo ""
echo -e "${BLUE}=== Results ===${NC}"
echo "Operation: ${OPERATION_TYPE} ${OPERATION_NAME}"
echo "Test case: ${TEST_CASE}"
echo ""
echo "Execution time WITHOUT proof generation: ${NO_PROOF_TIME_SEC} (${NO_PROOF_TIME}ms)"
echo "Execution time WITH proof generation:    ${WITH_PROOF_TIME_SEC} (${WITH_PROOF_TIME}ms)"
echo ""

# Calculate overhead
OVERHEAD_MS=$(($WITH_PROOF_TIME - $NO_PROOF_TIME))
OVERHEAD_SEC=$(format_time "$OVERHEAD_MS")
if [ "$NO_PROOF_TIME" -gt 0 ]; then
    MULTIPLIER=$(calculate_multiplier "$WITH_PROOF_TIME" "$NO_PROOF_TIME")
    echo -e "${YELLOW}Proof generation overhead:     ${OVERHEAD_SEC} (${OVERHEAD_MS}ms)${NC}"
    echo -e "${YELLOW}Multiplicative overhead:       ${MULTIPLIER}x${NC}"
fi

echo ""
echo -e "${BLUE}=== Summary ===${NC}"
echo "Baseline (no proof):  ${NO_PROOF_TIME_SEC}"
echo "With proof:          ${WITH_PROOF_TIME_SEC}"
echo "Overhead:            ${OVERHEAD_SEC} (${MULTIPLIER}x)"
echo ""
echo -e "${BLUE}=== Detailed Logs ===${NC}"
echo "Without proof: $NO_PROOF_LOG"
echo "With proof:    $WITH_PROOF_LOG"
