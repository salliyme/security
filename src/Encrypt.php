<?php

/*
 * author: salliyme@qq.com
 */

namespace salliyme\security;

class Encrypt
{
    // Block size for encryption block cipher
    private $ENCRYPT_BLOCK_SIZE = 200; // this for 2048 bit key for example, leaving some room

    // Block size for decryption block cipher
    private $DECRYPT_BLOCK_SIZE = 256; // this again for 2048 bit key

    private $privatePEMKey;
    private $publicPEMKey;

    public function generateKey()
    {
        $dn = array(
            'countryName' => 'CN',
            'stateOrProvinceName' => 'Sichuan',
            'localityName' => 'chengdu',
            'organizationName' => 'The SJCX Limited',
            'organizationalUnitName' => 'SJCX.LTD',
            'commonName' => 'sjcx.ltd',
            'emailAddress' => 'salliyme@qq.com'
        );

        // Generate a new private (and public) key pair
        $privKey = openssl_pkey_new(array(
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ));

        // Generate a certificate signing request
        $csr = openssl_csr_new($dn, $privKey, array('digest_alg' => 'sha256'));

        // Generate a self-signed cert, valid for 365 days
        $x509 = openssl_csr_sign($csr, null, $privKey, $days = 365, array('digest_alg' => 'sha256'));

        openssl_x509_export_to_file($x509, 'rsa-cert.pem');
        openssl_pkey_export_to_file($privKey, 'rsa-private.pem');
    }

    public function init() {
        $this->privatePEMKey = openssl_pkey_get_private("file://rsa-private.pem");
        $this->publicPEMKey = openssl_pkey_get_public("file://rsa-cert.pem");
    }

    public function private_encrypt($plainData)
    {
        $encrypted = '';
        $plainData = str_split($plainData, $this->ENCRYPT_BLOCK_SIZE);
        foreach ($plainData as $chunk) {
            $partialEncrypted = '';
            // using for example OPENSSL_PKCS1_PADDING as padding
            $encryptionOk = openssl_private_encrypt($chunk, $partialEncrypted, $this->privatePEMKey, OPENSSL_PKCS1_PADDING);
            if ($encryptionOk === false) { // also you can return and error. if to big this will be false
                return false;
            }
            $encrypted .= $partialEncrypted;
        }
        return base64_encode($encrypted); // encoding the whole binary string as MIME base 64
    }

    public function public_decrypt($data)
    {
        $decrypted = '';
        // decode must be done before splitting for getting the binary string
        $data = str_split(base64_decode($data), $this->DECRYPT_BLOCK_SIZE);
        foreach ($data as $chunk) {
            $partial = '';
            // be sure to match padding
            $decryptionOk = openssl_public_decrypt($chunk, $partial, $this->publicPEMKey, OPENSSL_PKCS1_PADDING);
            if ($decryptionOk === false) { // here also processed errors in decryption. If too big this will be false
                return false;
            }
            $decrypted .= $partial;
        }
        return $decrypted;
    }

    public function public_encrypt($plainData) {
        $encrypted = '';
        $plainData = str_split($plainData, $this->ENCRYPT_BLOCK_SIZE);
        foreach ($plainData as $chunk) {
            $encryptionOk = openssl_public_encrypt($chunk, $partialEncrypted, $this->publicPEMKey, OPENSSL_PKCS1_PADDING);
            if ($encryptionOk === false) {
                return false;
            }
            $encrypted .= $partialEncrypted;
        }
        return base64_encode($encrypted);
    }

    public function private_decrypt($data) {
        $decrypted = '';
        $data = str_split(base64_decode($data), $this->DECRYPT_BLOCK_SIZE);
        foreach ($data as $chunk) {
            $decryptionOk = openssl_private_decrypt($chunk, $partialDecrypted, $this->privatePEMKey, OPENSSL_PKCS1_PADDING);
            if ($decryptionOk === false) {
                return false;
            }
            $decrypted .= $partialDecrypted;
        }
        return $decrypted;
    }
}