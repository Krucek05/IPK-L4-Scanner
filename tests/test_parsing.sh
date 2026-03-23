#!/usr/bin/env bash

# Test script for ipk-L4-scan argument parsing

APP="./ipk-L4-scan"

# Compile first if not compiled
make > /dev/null 2>&1

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass_count=0
fail_count=0

run_test() {
    local cmd="$1"
    local expected_status="$2"
    local run_cmd="$APP $cmd"
    
    $run_cmd > /dev/null 2>&1
    local status=$?

    local is_pass=1
    if [ "$expected_status" -eq 0 ]; then
        if [ "$status" -ne 0 ]; then
            is_pass=0
        fi
    else
        if [ "$status" -eq 0 ]; then
            is_pass=0
        fi
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
echo "--- Valid Commands ---"
run_test "-h" 0
run_test "--help" 0
run_test "-i" 0
run_test "-i eth0 localhost" 0
run_test "-i eth0 -t 22 localhost" 0
run_test "-i eth0 -u 53 localhost" 0
run_test "-i eth0 -t 22,23 -u 53,67 localhost" 0
run_test "-i eth0 -t 1-100 localhost" 0
run_test "-i eth0 -w 2000 localhost" 0
run_test "-i eth0 -t 80 -w 500 www.vutbr.cz" 0
run_test "localhost -i eth0 -t 80" 0  # Order should not matter

# --- Invalid Commands & Errors ---
echo "--- Invalid Errors ---"
run_test "" 1                      # No arguments
run_test "-i 1 -1 5 Host"1         # Invalid interface name
run_test "-i eth0" 1               # Missing HOST
run_test "localhost" 1             # Missing -i
run_test "-i eth0 host1 host2" 1   # Multiple hosts
run_test "-i eth0 -t localhost" 1  # Missing port after -t
run_test "-i eth0 -u localhost" 1  # Missing port after -u
run_test "-i eth0 -w localhost" 1  # Invalid timeout value
run_test "-i eth0 -t 999999 localhost" 1 # Port out of range
run_test "-i eth0 -t -10 localhost" 1    # Negative port

echo "============================"
echo "Tests Completed. Passed: $pass_count, Failed: $fail_count"

if [ "$fail_count" -gt 0 ]; then
    exit 1
fi
exit 0
