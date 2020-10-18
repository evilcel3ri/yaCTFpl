#!/bin/bash
host=$1

for port in {1..65535}; do
    timeout .1 bash -c "</dev/tcp/$host/$port &>/dev/null"  &&  echo "port $port is open"
done
echo "Done!"
