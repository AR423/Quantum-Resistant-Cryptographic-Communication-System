#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <chrono>

// OpenSSL Headers
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

// OQS Header
#include <oqs/oqs.h>

#define AES_KEY_LEN 32  // 256 bits
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16
#define SEQUENCE_LEN 8

using namespace std;

class QuantumSecureChannel {
private:
    string kem_alg_name;
    vector<uint8_t> session_key;
    uint64_t my_sequence;
    uint64_t peer_sequence;
    double time_op_ms;

    void derive_session_key(const vector<uint8_t>& shared_secret);

public:
    QuantumSecureChannel(string alg);
    
    // KEM (Key Exchange)
    vector<uint8_t> generate_keypair(vector<uint8_t>& secret_key_storage);
    vector<uint8_t> encapsulate(const vector<uint8_t>& public_key);
    void decapsulate(const vector<uint8_t>& ciphertext, const vector<uint8_t>& secret_key);

    // Symmetric (AES-GCM)
    vector<uint8_t> encrypt(const string& plaintext);
    string decrypt(const vector<uint8_t>& payload);
};

#endif
