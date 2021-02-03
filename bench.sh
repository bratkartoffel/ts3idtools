#!/bin/sh
set -e

exe=$1
rounds=$2
if [ -z "$exe" ]; then exe=./ts3idcrunch; fi
if [ -z "$rounds" ]; then rounds=25; fi

sum=0
for i in $(seq 1 $rounds); do
  perf=$($exe --blocksize=22 --counter=10799000000000 \
    --publickey=MEwDAgcAAgEgAiEAyKQZKU/Sr2mZtT0T/R6g/BcnfU4vsgT2BfsZiwBrv60CIEpfLzajVLJtTzJwSINdUL0/AKriXwav1ffrymdHUmDC \
    --level=30 --threads=4 --one-shot | egrep '^Performance' | awk '{print $2}')
  sum=$(echo "$sum + $perf" | bc)
  echo "Round $i: $perf mh/s"
done

avg=$(echo "scale=2; $sum / $rounds" | bc)
echo "Average: $avg mh/s"
