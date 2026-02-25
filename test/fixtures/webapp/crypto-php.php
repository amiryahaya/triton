<?php
$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
$hash = hash('sha256', $data);
openssl_sign($data, $signature, $privKey, OPENSSL_ALGO_SHA256);
?>
