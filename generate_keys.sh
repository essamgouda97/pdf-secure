#!/bin/bash

# Generate key and nonce
key=$(openssl rand -hex 16)
nonce=$(openssl rand -hex 12)

# Replace text in file
sed -i "s/#### PLACE KEY AND NONCE HERE ####/pub const KEY: [u8; 32] = *b\"$key\";\npub const NONCE: [u8; 24] = *b\"$nonce\";/g" src/utils.rs