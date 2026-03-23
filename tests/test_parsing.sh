#!/usr/bin/env bash

# Test script for ipk-L4-scan argument parsing
# This tests were AI generated based on the expected behavior of the application and are meant to cover various valid and invalid input scenarios.
# Used mainly for testing the CLI parsing logic and error handling of the application.
# Tests were mostly replaced with new Criterion unit tests, but this script can still be useful for quick manual testing or as a reference for expected command formats.
APP="./ipk-L4-scan"

# Compile first if not compiled
make > /dev/null 2>&1

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# --- Interface Detection ---
# Run the app with -i, filter out 'lo', and take the first available name
DETECTED_IFACE=$(sudo $APP -i 2>/dev/null | grep -v "lo" | head -n 1 | awk '{print $1}')

if [ -z "$DETECTED_IFACE" ]; then
    echo -e "${RED}[ERROR]${NC} No active network interface detected via $APP -i"
    exit 1
fi

echo -e "${GREEN}[INFO]${NC} Using detected interface: $DETECTED_IFACE"
echo "============================"

pass_count=0
fail_count=0

run_test() {
    local cmd="$1"
    local expected_status="$2"
    # Replace the placeholder 'IFACE' with our detected interface
    local processed_cmd=$(echo "$cmd" | sed "s/IFACE/$DETECTED_IFACE/g")
    local run_cmd="sudo $APP $processed_cmd"
    
    $run_cmd > /dev/null 2>&1
    local status=$?

    local is_pass=1
    if [ "$expected_status" -eq 0 ]; then
        [ "$status" -ne 0 ] && is_pass=0
    else
        [ "$status" -eq 0 ] && is_pass=0
    fi

    if [ "$is_pass" -eq 1 ]; then
        echo -e "${GREEN}[PASS]${NC} $run_cmd"
        ((pass_count++))
    else
        echo -e "${RED}[FAIL]${NC} $run_cmd (Expected error: $expected_status, Got: $status)"
        ((fail_count++))
    fi
}

echo "Running CLI Parsing Tests..."
echo "============================"

# --- Valid Commands ---
# Note: Using 'IFACE' as a placeholder that gets swapped for the real name
echo "--- Valid Commands ---"
run_test "-h" 0
run_test "--help" 0
run_test "-i" 0
run_test "-i IFACE -t 22 localhost" 0
run_test "-i IFACE -u 53 localhost" 0
run_test "-i IFACE -t 22,23 -u 53,67 localhost" 0
run_test "-i IFACE -t 1-10 localhost" 0
run_test "-i IFACE -t 80 -w 500 www.vutbr.cz" 0
run_test "localhost -i IFACE -t 80" 0 

# --- Invalid Commands & Errors ---
echo -e "\n--- Invalid/Error Cases ---"
run_test "" 1 
run_test "-i 1 -1 5 Host" 1
run_test "-i IFACE localhost" 1
run_test "-i IFACE" 1 
run_test "localhost" 1 
run_test "-i IFACE -w 2000 localhost" 1
run_test "-i IFACE host1 host2" 1 
run_test "-i IFACE -t localhost" 1 
run_test "-i IFACE -u localhost" 1 
run_test "-i IFACE -w localhost" 1 
run_test "-i IFACE -t 999999 localhost" 1 
run_test "-i IFACE -t -10 localhost" 1 

echo "============================"
echo "Tests Completed. Passed: $pass_count, Failed: $fail_count"

if [ "$fail_count" -gt 0 ]; then
    exit 1
fi
exit 0