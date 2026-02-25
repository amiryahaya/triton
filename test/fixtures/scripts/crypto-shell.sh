#!/bin/bash
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 365
openssl enc -aes-256-cbc -in plaintext.txt -out encrypted.txt
openssl dgst -sha256 -sign key.pem -out signature.bin data.txt
