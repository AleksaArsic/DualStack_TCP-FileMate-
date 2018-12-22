#pragma once

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "conio.h"
#include <deque>
#include <mutex>

#define SERVER_DESC "FileMate Server - a simple file sharing application" // Description of application

#define SERVER_PORT 27015	// Port number of server that will be used for communication with clients
#define BUFFER_SIZE 512		// Size of buffer that will be used for sending and receiving messages to clients
#define SEND_DENOM 4        // How much parts will sending file have
#define IPv4_ADDR_LEN 15    // IPv4 address length
#define THREAD_SLEEP 200   // Thread sleep coeficient, determines the speed of file transfer

#define FILE_NAME "transfer\\output.dat" // location and name of file for transfering

// Data to be available to threads
struct threadData {
    SOCKET clientSocket;
    sockaddr_in6 clientAddress;
    int sockAddrLen;
};

// Active connections by one IPv4 address
struct aConnectionsIPv4 {
    char clientAddress[IPv4_ADDR_LEN];
    unsigned int opConnections;
};

// Active connections by one IPv6 address
struct aConnectionsIPv6 {
    char clientAddress[INET6_ADDRSTRLEN];
    unsigned int opConnections;
};

// Deques of active connections
std::deque<aConnectionsIPv4> IPv4Connections;
std::deque<aConnectionsIPv6> IPv6Connections;

// Mutex for critical sections
std::mutex dequeMutex;

// Processing thread
DWORD WINAPI SystemThread(void* data);
// Checks if ip address belongs to IPv4 address family
bool is_ipV4_address(sockaddr_in6 address);
// Print information to whom file is sent
void printSentInfo(const sockaddr_in6 clientAddress, const float bytesReceived);
// Return file size 
unsigned long long int fileSize(FILE* filePtr);
// Return remainder of the division when dividing file size on smaller packets
int fileRemainder(unsigned long long int toSend, unsigned long long int fileSize);
// Add new connection to the deque of active connections
int addConnection(sockaddr_in6 clientAddress);
// Find connection in deque of IPv4 active connections
aConnectionsIPv4 findIPv4Connection(sockaddr_in6 clientAddress);
// Find connection in deque of IPv6 active connections
aConnectionsIPv6 findIPv6Connection(sockaddr_in6 clientAddress);
// Find connection in deque of IPv4 active connections and return its index
unsigned int findIPv4ConnectionIndex(sockaddr_in6 clientAddress);
// Find connection in deque of IPv6 active connections and return its index
unsigned int findIPv6ConnectionIndex(sockaddr_in6 clientAddress);
