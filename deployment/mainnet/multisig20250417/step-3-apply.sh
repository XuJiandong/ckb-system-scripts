#!/bin/bash

ckb-cli --url https://mainnet.ckb.dev deploy apply-txs --zero-lock --migration-dir ./migrations --info-file info.json
