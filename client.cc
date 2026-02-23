#include "network.h"

void run_client(string alg_name) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) throw runtime_error("Socket creation failed");

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        throw runtime_error("Connection Failed. Ensure server is running.");
    }

    QuantumSecureChannel qs(alg_name);

    // 1. Handshake
    vector<uint8_t> pk = recv_data(sock);
    if (pk.empty()) throw runtime_error("Server disconnected during handshake.");
    
    vector<uint8_t> ct = qs.encapsulate(pk);
    send_data(sock, ct);
    
    cout << "[*] Secure Session Established. Type 'exit' to quit." << endl;
    cout << "------------------------------------------------------" << endl;
    
    // 2. Chat Threads
    thread receiver(receive_loop, sock, &qs);

    string input;
    while (!terminate_flag.load() && cout << "[You]: " && getline(cin, input)) {
        if (input == "exit") {
            terminate_flag = true;
            break;
        }
        if (input.empty()) continue;

        try {
            send_data(sock, qs.encrypt(input));
        } catch (const exception& e) {
            cerr << "[!] Send Error: " << e.what() << endl;
            terminate_flag = true;
            break;
        }
    }
    
    if (receiver.joinable()) {
        shutdown(sock, SHUT_RDWR);
        receiver.join();
    }
    close(sock);
}

int main(int argc, char const *argv[]) {
    if(argc < 2) {
        cout << "Usage: ./client [alg_name]" << endl;
        return 1;
    }
    try {
        OQS_init();
        run_client(argv[1]);
        OQS_destroy();
    } catch (const exception& e) {
        cerr << "FATAL ERROR: " << e.what() << endl;
        return 1;
    }
    return 0;
}
