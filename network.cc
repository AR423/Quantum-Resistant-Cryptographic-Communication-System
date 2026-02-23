#include "network.h"

// Define the global flag here
std::atomic<bool> terminate_flag(false);

void send_data(int sock, const vector<uint8_t>& data) {
    uint32_t len = htonl(data.size());
    // Send 4-byte length header
    send(sock, &len, 4, 0);
    
    // Send data in chunks
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t sent = send(sock, data.data() + total_sent, data.size() - total_sent, 0);
        if (sent <= 0) break; // Error or socket closed
        total_sent += sent;
    }
}

vector<uint8_t> recv_data(int sock) {
    uint32_t len;
    // Receive 4-byte length header
    int n = recv(sock, &len, 4, 0);
    if (n != 4) return {}; // Failed to read header

    len = ntohl(len);
    if (len == 0) return {};

    vector<uint8_t> buf(len);
    size_t total = 0;
    while(total < len) {
        n = recv(sock, buf.data() + total, len - total, 0);
        if(n <= 0) return {};
        total += n;
    }
    return buf;
}

void receive_loop(int sock, QuantumSecureChannel* qs) {
    while (!terminate_flag.load()) {
        vector<uint8_t> enc_msg = recv_data(sock);
        
        // If socket closed or error
        if(enc_msg.empty()) {
            if (!terminate_flag.load()) { 
                cout << "\r[!] Peer disconnected. Press Enter to exit." << endl;
            }
            terminate_flag = true;
            break;
        }
        
        try {
            string msg = qs->decrypt(enc_msg);
            // Fancy console output to not break the input line
            cout << "\r[Peer]: " << msg << endl; 
            cout << "[You]: " << flush; 
        } catch (exception& e) {
            cout << "\r[!] Security Alert: " << e.what() << endl;
            terminate_flag = true;
            break;
        }
    }
}
