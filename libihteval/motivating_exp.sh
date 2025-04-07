#!/bin/bash

# List of workloads (name and command)
declare -A WORKLOADS=(
  ["echo"]="echo 'hello world'"
  ["ls"]="ls -lah /bin > /dev/null"
  ["cat"]="cat /etc/passwd > /dev/null"
  ["dd"]="dd if=/dev/zero of=/dev/null bs=1M count=100"
  ["sort"]="sort < /etc/passwd > /dev/null"
  ["wc"]="wc -l < /etc/passwd > /dev/null"
  ["tar"]="tar -cf /dev/null /etc > /dev/null"
)

# Tools
PIN_CMD="pin --"
DRRUN_CMD="drrun -root $DYNAMORIO_HOME --"

# Helper to get current time in milliseconds
get_time_ms() {
  date +%s%3N
}

# Output format
print_result() {
  printf "%-10s | %-8s | %6s ms\n" "$1" "$2" "$3"
}

echo "Benchmarking workloads (native, pin, dynamorio) in ms"
echo "------------------------------------------------------------"
printf "%-10s | %-8s | %s\n" "Workload" "Mode" "Time"
echo "------------------------------------------------------------"

for name in "${!WORKLOADS[@]}"; do
  cmd="${WORKLOADS[$name]}"

  # Native
  start=$(get_time_ms)
  bash -c "$cmd" > /dev/null 2>&1
  end=$(get_time_ms)
  native_time=$((end - start))
  print_result "$name" "native" "$native_time"

  # Pin
  start=$(get_time_ms)
  bash -c "$PIN_CMD $cmd" > /dev/null 2>&1
  end=$(get_time_ms)
  pin_time=$((end - start))
  print_result "$name" "pin" "$pin_time"

  # DynamoRIO
  start=$(get_time_ms)
  bash -c "$DRRUN_CMD $cmd" > /dev/null 2>&1
  end=$(get_time_ms)
  drrun_time=$((end - start))
  print_result "$name" "drrun" "$drrun_time"

  echo "------------------------------------------------------------"
done