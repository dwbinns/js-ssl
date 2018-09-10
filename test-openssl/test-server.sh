#!/bin/bash

{ echo world; sleep 1; } | ./openssl-1.0.2k/apps/openssl s_server -key key.pem -cert cert.pem "$@" -cipher DES-CBC-SHA -accept 1443 > >(sed -re 's/^/SERVER: /') 2>&1 & PID=$!

sleep 1

{ echo hello; sleep 1; } | node ../src/cli.js client tls1.0 localhost:1443 > >(sed -re 's/^/CLIENT: /') 2>&1

kill $PID
