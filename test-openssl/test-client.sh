#!/bin/bash
node ../src/cli.js server tls1.0 cert.pem key.pem localhost:1443 > >(sed -re 's/^/SERVER: /') 2>&1 & PID=$!
sleep 1
{ echo hi; sleep 1; } | ./openssl-1.0.2k/apps/openssl s_client -state "$@" -connect localhost:1443  > >(sed -re 's/^/CLIENT: /') 2>&1
kill $PID
