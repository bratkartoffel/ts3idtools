#!/bin/sh

for i in $(seq 1 10); do
  ./ts3idcrunch --blocksize=22 --counter=10799700000000 --publickey=MEwDAgcAAgEgAiEAyKQZKU/Sr2mZtT0T/R6g/BcnfU4vsgT2BfsZiwBrv60CIEpfLzajVLJtTzJwSINdUL0/AKriXwav1ffrymdHUmDC \
    --level=26 --threads=2 --one-shot --stats-interval=5 | egrep '^(Performance|Results)'
done

./ts3idgen | egrep ^identity= | cut -d\" -f2 | xargs ./ts3iddump -i | egrep ^PublicKey= | cut -d= -f2 | xargs ./ts3idcrunch -o -l 30 -t 4 -s 10 -p
