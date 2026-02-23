#ifndef NETWORK_HPP
#define NETWORK_HPP

#include "crypto.h"
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <atomic>

#define PORT 65432

// Flag to control the receive loop threads
extern std::atomic<bool> terminate_flag;

void send_data(int sock, const vector<uint8_t>& data);
vector<uint8_t> recv_data(int sock);
void receive_loop(int sock, QuantumSecureChannel* qs);

#endif
