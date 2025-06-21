#!/bin/bash
set -e

readonly exe=$1

readonly count_rounds=20
readonly duration=10
readonly count_threads=$(nproc)
readonly pubkey=MEsDAgcAAgEgAiA0jNBZiv2DHBIJw+dwExW/pBZNoJMDXsTmdTjN3/19jQIgPq1I1CLck2vf8a2FfvLaO2C0ocxhUWNqPedG5nVHW3o=

for threads in $(seq 1 $count_threads); do
  sum=0
  for round in $(seq 1 $count_rounds); do
    perf=$(
    timeout -s SIGINT $duration \
      "$exe" \
        -t "$threads" \
        -p "$pubkey" \
        -l 64 \
        -b 23 \
        -c 100000000000000 \
          | grep -E "^Performance" \
          | awk '{print $2}'
    )
    sum=$(echo "$sum + $perf" | bc)
    echo "$threads threads, round $round: $perf mh/s"
  done

  avg=$(echo "scale=2; $sum / $count_rounds" | bc)
  avg2=$(echo "scale=2; $sum / $count_rounds / $threads" | bc)
  echo "$threads threads average: $avg mh/s ($avg2 mh/s per thread)"
done
