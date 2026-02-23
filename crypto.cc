#include "crypto.h"

// The global std::atomic<bool> terminate_flag is defined in network.cpp

QuantumSecureChannel::QuantumSecureChannel(string alg) 
    : kem_alg_name(alg), my_sequence(0), peer_sequence(0), time_op_ms(0) {}

vector<uint8_t> QuantumSecureChannel::generate_keypair(vector<uint8_t>& secret_key_storage) {
    auto start = std::chrono::high_resolution_clock::now();
    OQS_KEM *kem = OQS_KEM_new(kem_alg_name.c_str());
    if (kem == NULL) throw runtime_error("KEM algorithm not found/enabled");

    vector<uint8_t> public_key(kem->length_public_key);
    secret_key_storage.resize(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, public_key.data(), secret_key_storage.data()) != OQS_SUCCESS)
        throw runtime_error("OQS Keypair generation failed");

    OQS_KEM_free(kem);
    
    auto end = std::chrono::high_resolution_clock::now();
    
    time_op_ms = std::chrono::duration<double, std::milli>(end - start).count(); 
    
    // --- METRICS ---
    cout << "[Metric] Key Gen Time: " << time_op_ms << " ms" << endl;
    cout << "[Metric] Public Key Size: " << public_key.size() << " bytes" << endl;
    cout << "[Metric] Secret Key Size: " << secret_key_storage.size() << " bytes" << endl;
    
    return public_key;
}

vector<uint8_t> QuantumSecureChannel::encapsulate(const vector<uint8_t>& public_key) {
    auto start = std::chrono::high_resolution_clock::now();
    OQS_KEM *kem = OQS_KEM_new(kem_alg_name.c_str());
    
    vector<uint8_t> ciphertext(kem->length_ciphertext);
    vector<uint8_t> shared_secret(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, ciphertext.data(), shared_secret.data(), public_key.data()) != OQS_SUCCESS)
        throw runtime_error("OQS Encapsulation failed");

    OQS_KEM_free(kem);
    derive_session_key(shared_secret);

    auto end = std::chrono::high_resolution_clock::now();
    
    // Convert KEM time to milliseconds
    time_op_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // --- METRICS ---
    cout << "[Metric] Encaps Time: " << time_op_ms << " ms" << endl;
    cout << "[Metric] KEM Ciphertext Size: " << ciphertext.size() << " bytes" << endl;
    cout << "[Metric] Shared Secret Size: " << shared_secret.size() << " bytes" << endl;
    // ---------------

    return ciphertext;
}

void QuantumSecureChannel::decapsulate(const vector<uint8_t>& ciphertext, const vector<uint8_t>& secret_key) {
    auto start = std::chrono::high_resolution_clock::now();
    OQS_KEM *kem = OQS_KEM_new(kem_alg_name.c_str());
    vector<uint8_t> shared_secret(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, shared_secret.data(), ciphertext.data(), secret_key.data()) != OQS_SUCCESS)
        throw runtime_error("OQS Decapsulation failed");

    OQS_KEM_free(kem);
    derive_session_key(shared_secret);
    
    auto end = std::chrono::high_resolution_clock::now();
    
    // Convert KEM time to milliseconds
    time_op_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // --- METRICS ---
    cout << "[Metric] Decaps Time: " << time_op_ms << " ms" << endl;
    cout << "[Metric] Shared Secret Size: " << shared_secret.size() << " bytes" << endl;
    // ---------------
}

void QuantumSecureChannel::derive_session_key(const vector<uint8_t>& shared_secret) {
    session_key.resize(AES_KEY_LEN);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned int len = 0;
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, shared_secret.data(), shared_secret.size());
    EVP_DigestFinal_ex(mdctx, session_key.data(), &len);
    EVP_MD_CTX_free(mdctx);
    
    // --- METRICS ---
    cout << "[Metric] Session Key Size: " << session_key.size() << " bytes (256-bit AES)" << endl;
    // ---------------
}

vector<uint8_t> QuantumSecureChannel::encrypt(const string& plaintext) {
    auto start = std::chrono::high_resolution_clock::now(); // Start timing
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t iv[GCM_IV_LEN] = {0};
    uint64_t seq_net = __builtin_bswap64(my_sequence);
    memcpy(iv, &seq_net, 8); 

    vector<uint8_t> encrypted_data(plaintext.size() + 16); 
    int outlen = 0;
    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, session_key.data(), iv);

    EVP_EncryptUpdate(ctx, encrypted_data.data(), &outlen, (uint8_t*)plaintext.c_str(), plaintext.size());
    len = outlen;
    EVP_EncryptFinal_ex(ctx, encrypted_data.data() + len, &outlen);
    len += outlen;
    encrypted_data.resize(len);

    vector<uint8_t> tag(GCM_TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    vector<uint8_t> final_payload;
    final_payload.insert(final_payload.end(), (uint8_t*)&seq_net, (uint8_t*)&seq_net + SEQUENCE_LEN); 
    final_payload.insert(final_payload.end(), encrypted_data.begin(), encrypted_data.end());
    final_payload.insert(final_payload.end(), tag.begin(), tag.end());

    my_sequence++;
    
    auto end = std::chrono::high_resolution_clock::now(); // End timing

    // Calculate time in nanoseconds, then report in microseconds (us)
    time_op_ms = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    // --- METRICS ---
    cout << "[Metric] Message Encrypt Time: " << time_op_ms / 1000.0 << " us" << endl;
    cout << "[Metric] Encrypted Payload Size: " << final_payload.size() << " bytes" << endl;
    // ---------------

    return final_payload;
}

string QuantumSecureChannel::decrypt(const vector<uint8_t>& payload) {
    auto start = std::chrono::high_resolution_clock::now(); // Start timing

    if (payload.size() < SEQUENCE_LEN + GCM_TAG_LEN) throw runtime_error("Payload too short");

    uint8_t iv[GCM_IV_LEN] = {0};
    uint64_t received_seq_net;
    memcpy(&received_seq_net, payload.data(), SEQUENCE_LEN); 
    memcpy(iv, &received_seq_net, SEQUENCE_LEN);
    uint64_t received_seq = __builtin_bswap64(received_seq_net);

    if (received_seq < peer_sequence) 
        throw runtime_error("Replay Attack Detected! Old sequence number.");

    size_t ciphertext_len = payload.size() - SEQUENCE_LEN - GCM_TAG_LEN;
    const uint8_t* ciphertext_ptr = payload.data() + SEQUENCE_LEN;
    const uint8_t* tag_ptr = payload.data() + SEQUENCE_LEN + ciphertext_len;
    
    vector<uint8_t> plaintext(ciphertext_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen, len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, session_key.data(), iv);

    EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext_ptr, ciphertext_len);
    len = outlen;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void*)tag_ptr);

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    
    auto end = std::chrono::high_resolution_clock::now(); // End timing

    // Calculate time in nanoseconds, then report in microseconds (us)
    time_op_ms = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count(); 

    // --- METRICS ---
    cout << "[Metric] Message Decrypt Time: " << time_op_ms / 1000.0 << " us" << endl;

    if (ret > 0) {
        peer_sequence = received_seq + 1; 
        return string(plaintext.begin(), plaintext.begin() + len + outlen); 
    } else {
        throw runtime_error("Integrity Check Failed! Tag mismatch.");
    }
}
