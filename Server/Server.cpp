// TCP server that use blocking sockets

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include "conio.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define SERVER_PORT 27015	// Port number of server that will be used for communication with clients
#define BUFFER_SIZE 512		// Size of buffer that will be used for sending and receiving messages to clients
#define SEND_DENOM 4        // How much parts will sending file have

#define SERVER_READY "Server ready for transfer." // Indicates that server is ready for file transfer
#define FILE_NAME "transfer\\output.dat" // location and name of file for transfering

struct threadData {
    SOCKET clientSocket;
    sockaddr_in6 clientAddress;
    int sockAddrLen;
};

// Processing thread
DWORD WINAPI SystemThread(void* data);
// Checks if ip address belongs to IPv4 address family
bool is_ipV4_address (sockaddr_in6 address);
// Print information to whom file is sent
void printSentInfo (const sockaddr_in6 clientAddress, const float bytesReceived);
// Return file size 
unsigned long long int fileSize (FILE* filePtr);
// Return remainder of the division when dividing file size on smaller packets
int fileRemainder (unsigned long long int toSend, unsigned long long int fileSize);

int main ()
{
    // Server address 
    sockaddr_in6 serverAddress; 

	// WSADATA data structure that is to receive details of the Windows Sockets implementation
    WSADATA wsaData;

	// Initialize windows sockets library for this process
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
    {
        printf("WSAStartup failed with error: %d\n", WSAGetLastError());
        return 1;
    }

    // Initialize serverAddress structure used by bind function
	memset((char*)&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin6_family = AF_INET6; 			// set server address protocol family
    serverAddress.sin6_addr = in6addr_any;			// use all available addresses of server
    serverAddress.sin6_port = htons(SERVER_PORT);	// Set server port
	serverAddress.sin6_flowinfo = 0;				// flow info

    SOCKET serverSocket = socket(AF_INET6, // IPv6 address family
                                SOCK_STREAM, // stream socket
                                IPPROTO_TCP); // TCP

	// Check if socket creation succeeded
    if (serverSocket == INVALID_SOCKET)
    {
        printf("Creating socket failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
	// Disable receiving only IPv6 packets. We want to receive both IPv4 and IPv6 packets.
	int no = 0;     
	int iResult = setsockopt(serverSocket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no));
	
	if (iResult == SOCKET_ERROR) 
			printf("failed with error: %u\n", WSAGetLastError());


    // Bind server address structure (type, port number and local address) to socket
    iResult = bind(serverSocket,(SOCKADDR *)&serverAddress, sizeof(serverAddress));

	// Check if socket is succesfully binded to server datas
    if (iResult == SOCKET_ERROR)
    {
        printf("Socket bind failed with error: %d\n", WSAGetLastError());
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    listen(serverSocket, SOMAXCONN); // Listen on serverSocket, maximum queue is a reasonable number

	printf("Simple TCP server waiting client messages.\n");

    // Main server loop
    while(1)
    {
        // Thread handlers
        DWORD threadId;
        HANDLE threadHandle;

        // Thread parameter
        struct threadData tData;

        // Declare and initialize client address that will be set from recvfrom
        sockaddr_in6 clientAddress;
		memset(&clientAddress, 0, sizeof(clientAddress));
        
		// size of client address
		int sockAddrLen = sizeof(clientAddress);

        SOCKET clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, (socklen_t*)&sockAddrLen);
        
        if (clientSocket < 0) {
            perror("accept failed");
            continue;
        }
        else {
            printf("Connection accepted.\n");
        }

        tData.clientSocket = clientSocket;
        tData.clientAddress = clientAddress;
        tData.sockAddrLen = sockAddrLen;
	
        threadHandle = CreateThread(NULL, 0, SystemThread, (LPVOID) &tData, 0, &threadId);

        // Possible server-shutdown logic could be put here
    }

    // Close server application
    iResult = closesocket(serverSocket);
    if (iResult == SOCKET_ERROR)
    {
        printf("closesocket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
        return 1;
    }
	
	printf("Server successfully shut down.\n");
	
	// Close Winsock library
	WSACleanup();
	_getch();
	return 0;
}

bool is_ipV4_address (sockaddr_in6 address)
{
	char *check = (char*)&address.sin6_addr.u;

	for (int i = 0; i < 10; i++)
		if(check[i] != 0)
			return false;
		
	if(check[10] != -1 || check[11] != -1)
		return false;

	return true;
}

DWORD WINAPI SystemThread (void* data)
{
    // File operators 
    FILE* filePtr;
    float bytesSent = 0;
    unsigned long long fSize = 0;
    long long leftToSend = 0;

    // Result of sendto operation 
    int iResult;

    // Unpack void* data structure 
    struct threadData* tData = (struct threadData *) data;
    SOCKET clientSocket = tData->clientSocket;
    sockaddr_in6 clientAddress = tData->clientAddress;
    int sockAddrLen = tData->sockAddrLen;

    // Buffer we will use to send and receive clients' messages
    char dataBuffer[BUFFER_SIZE];

    // Set whole buffer to zero
    memset(dataBuffer, 0, BUFFER_SIZE);
    // Copy SERVER_READY info to dataBuffer
    strcpy(dataBuffer, SERVER_READY);

    // Send message to client
    iResult = sendto(clientSocket,						// Own socket
                        dataBuffer,						// Text of message
                        strlen(dataBuffer),				// Message size
                        0,								// No flags
                        (SOCKADDR *)&clientAddress,		// Address structure of server (type, IP address and port)
                        sizeof(clientAddress));			// Size of sockadr_in structure

    // Check if message is succesfully sent. If not, close client/server session
    if (iResult == SOCKET_ERROR)
    {
        printf("sendto failed with error: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        ExitThread(100);
    }

    // Set whole buffer to zero
    memset(dataBuffer, 0, BUFFER_SIZE);

    iResult = recvfrom(clientSocket,						// Own socket
                        dataBuffer,							// Buffer that will be used for receiving message
                        BUFFER_SIZE,						// Maximal size of buffer
                        0,									// No flags
                        (struct sockaddr *)&clientAddress,	// Client information from received message (ip address and port)
                        &sockAddrLen);						// Size of sockadd_in structure


    // Check if message is succesfully received
    if (iResult == SOCKET_ERROR)
    {
        printf("recv failed with error: %d\n", WSAGetLastError());
        return 1;
    }

    // Part of file to send to client
    int partToSend = dataBuffer[0] - '0';

    Sleep(500);

    // Set whole buffer to zero
    memset(dataBuffer, 0, BUFFER_SIZE);

    // Open file for reading
    filePtr = fopen(FILE_NAME, "r");

    if (filePtr == NULL)
    {
        printf("Error opening file.\n");
        ExitThread(100);
    }

    // Retreive file size
    fSize = fileSize(filePtr);

    int fRemainder = 0;

    // How much bytes to send
    if (fSize >= SEND_DENOM)
    {
        leftToSend = fSize / SEND_DENOM;
        fRemainder = fileRemainder(leftToSend, fSize);
        if (partToSend == SEND_DENOM && fRemainder != 0)
        {
            leftToSend += fRemainder;
        }
    }
    else
    {
        leftToSend = fSize;
    }

    int fpOffset = leftToSend * (partToSend - 1);

    fseek(filePtr, fpOffset, SEEK_SET);

    int i = 0;
    char cFromFile;

    while(leftToSend != 0)
    {

        cFromFile = fgetc(filePtr);
        dataBuffer[i++] = cFromFile;

        if (cFromFile == '\n') leftToSend--;

        leftToSend--;
        bytesSent++;

        if (strlen(dataBuffer) == (BUFFER_SIZE - 1) || leftToSend == 0)
        {
            // Send message to client
            iResult = sendto(clientSocket,						// Own socket
                                dataBuffer,						// Text of message
                                strlen(dataBuffer),				// Message size
                                0,								// No flags
                                (SOCKADDR *)&clientAddress,		// Address structure of server (type, IP address and port)
                                sizeof(clientAddress));			// Size of sockadr_in structure

            // Check if message is succesfully sent. If not, close client/server session
            if (iResult == SOCKET_ERROR)
            {
                printf("sendto failed with error: %d\n", WSAGetLastError());
                closesocket(clientSocket);
                WSACleanup();
                ExitThread(100);
            }

            // Set whole buffer to zero
            memset(dataBuffer, 0, BUFFER_SIZE);

            i = 0;
        }
    }

    // Set whole buffer to zero
    memset(dataBuffer, 0, BUFFER_SIZE);

    strcpy(dataBuffer, "EOF\0");

    // Sleep thread so the client side can flush input stream
    // before "EOF\0" is sent
    Sleep(2000);

    // Send message to client
    iResult = sendto(clientSocket,						// Own socket
                        dataBuffer,						// Text of message
                        strlen(dataBuffer),				// Message size
                        0,								// No flags
                        (SOCKADDR *)&clientAddress,		// Address structure of server (type, IP address and port)
                        sizeof(clientAddress));			// Size of sockadr_in structure

    // Check if message is succesfully sent. If not, close client/server session
    if (iResult == SOCKET_ERROR)
    {
        printf("sendto failed with error: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        ExitThread(100);
    }

    // Set whole buffer to zero
    memset(dataBuffer, 0, BUFFER_SIZE);

    fclose(filePtr);

    // Print client information
    printSentInfo(clientAddress, bytesSent);

    // Exit thread successfully 
    ExitThread(0);
}

void printSentInfo (const sockaddr_in6 clientAddress, const float bytesSent)
{

    char ipAddress[INET6_ADDRSTRLEN]; // INET6_ADDRSTRLEN 65 spaces for hexadecimal notation of IPv6

    // Copy client ip to local char[]
    inet_ntop(clientAddress.sin6_family, &clientAddress.sin6_addr, ipAddress, sizeof(ipAddress));

    // Convert port number from network byte order to host byte order
    unsigned short clientPort = ntohs(clientAddress.sin6_port);

    bool isIPv4 = is_ipV4_address(clientAddress); //true for IPv4 and false for IPv6

    if (isIPv4) {
        char ipAddress1[15]; // 15 spaces for decimal notation (for example: "192.168.100.200") + '\0'
        struct in_addr *ipv4 = (struct in_addr*)&((char*)&clientAddress.sin6_addr.u)[12];

        // Copy client ip to local char[]
        strcpy_s(ipAddress1, sizeof(ipAddress1), inet_ntoa(*ipv4));
        printf("IPv4 Client connected from ip: %s, port: %d, received: %.2f kB.\n", ipAddress1, clientPort, bytesSent / 1024 );
    }
    else
        printf("IPv6 Client connected from ip: %s, port: %d, received: %.2f kB.\n", ipAddress, clientPort, bytesSent / 1024);

}

unsigned long long int fileSize (FILE* filePtr)
{
    unsigned long long int fSize = 0;

    fseek(filePtr, 0, SEEK_END);
    fSize = ftell(filePtr);
    rewind(filePtr);

    return fSize;
}

int fileRemainder (unsigned long long int toSend, unsigned long long int fileSize)
{
    int remainder = 0;
    unsigned long long int fileSizeCalc = 0;

    fileSizeCalc = toSend * SEND_DENOM;
    remainder = fileSize - fileSizeCalc;

    return remainder;
}