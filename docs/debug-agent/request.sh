#!/usr/bin/env bash

../../ch-k8s-lbaas-agent -logtostderr -v 5 -config $PWD/agent-config.toml&
agent_pid=$!

sleep 1

./request.py

kill $!

cat nftables.conf
