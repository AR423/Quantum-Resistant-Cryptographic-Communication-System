#include "network.h"
// crypto.hpp is included via network.hpp

void run_server(string alg_name) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        throw runtime_error("Bind failed");
    }
    if (listen(server_fd, 3) < 0) {
        throw runtime_error("Listen failed");
    }
    
    cout << "[*] Server listening (" << alg_name << ")..." << endl;
    new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    if (new_socket < 0) {
        throw runtime_error("Accept failed");
    }

    QuantumSecureChannel qs(alg_name);
    
    // 1. Handshake
    vector<uint8_t> sk;
    vector<uint8_t> pk = qs.generate_keypair(sk);
    send_data(new_socket, pk);
    
    vector<uint8_t> ct = recv_data(new_socket);
    if (ct.empty()) throw runtime_error("Client disconnected during handshake.");
    qs.decapsulate(ct, sk);
    
    cout << "[*] Secure Session Established. Type 'exit' to quit." << endl;
    cout << "------------------------------------------------------" << endl;

    // 2. Chat Threads
    thread receiver(receive_loop, new_socket, &qs);
    
    string input;
    while (!terminate_flag.load() && cout << "[You]: " && getline(cin, input)) {
        if (input == "exit") {
            terminate_flag = true;
            break;
        }
        if (input.empty()) continue;

        try {
            send_data(new_socket, qs.encrypt(input));
        } catch (const exception& e) {
            cerr << "[!] Send Error: " << e.what() << endl;
            terminate_flag = true;
            break;
        }
    }
    
    if (receiver.joinable()) {
        shutdown(new_socket, SHUT_RDWR);
        receiver.join();
    }
    close(new_socket);
    close(server_fd);
}

int main(int argc, char const *argv[]) {
    if(argc < 2) {
        cout << "Usage: ./server [alg_name]" << endl;
        return 1;
    }
    try {
        OQS_init();
        run_server(argv[1]);
        OQS_destroy();
    } catch (const exception& e) {
        cerr << "FATAL ERROR: " << e.what() << endl;
        return 1;
    }
    return 0;
}
