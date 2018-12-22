// TCP server that use blocking sockets

#define WIN32_LEAN_AND_MEAN

#include <stdlib.h>
#include <stdio.h>
#include "Server.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

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

	printf("%s\n", SERVER_DESC);

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
    // Result of adding new connection to deque
    int dequeRes;

    // Unpack void* data structure 
    struct threadData* tData = (struct threadData *) data;
    SOCKET clientSocket = tData->clientSocket;
    sockaddr_in6 clientAddress = tData->clientAddress;
    int sockAddrLen = tData->sockAddrLen;

    // Buffer we will use to send and receive clients' messages
    char dataBuffer[BUFFER_SIZE];

    // Set whole buffer to zero
    memset(dataBuffer, 0, BUFFER_SIZE);

    // How much parts of the file should client recieve 
    char noOfParts[2];
    noOfParts[0] = SEND_DENOM + '0';
    noOfParts[1] = 0;
    // Copy SERVER_READY info to dataBuffer
    strcpy(dataBuffer, noOfParts);

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

    // Add IP address to dequeu of active connections (either IPv4 or IPv6)
    // This is a critical section
    dequeMutex.lock();
    dequeRes = addConnection(clientAddress);
    dequeMutex.unlock();

    if (dequeRes)
    {
        printf("Error! Something wrong with IP address.\n");
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

    // File size remainder
    int fRemainder = 0;

    // How much bytes to send
    if (fSize >= SEND_DENOM)
    {
        leftToSend = fSize / SEND_DENOM;
        
        // Calculate and set remainder only if it is the last part of the file to transfer 
        if (partToSend == SEND_DENOM && fRemainder != 0)
        {
            fRemainder = fileRemainder(leftToSend, fSize);
            leftToSend += fRemainder;
        }
    }
    else
    {
        leftToSend = fSize;
    }

    unsigned int fpOffset = (leftToSend - fRemainder) * (partToSend - 1);

    fseek(filePtr, fpOffset, SEEK_SET);

    int i = 0;
    char cFromFile;

    bool isIPv4 = is_ipV4_address(clientAddress); //true for IPv4 and false for IPv6

    // Send Processing
    while(leftToSend != 0)
    {

        cFromFile = fgetc(filePtr);
        dataBuffer[i++] = cFromFile;

        if (cFromFile == '\n') leftToSend--;

        leftToSend--;
        bytesSent++;

        if (strlen(dataBuffer) == (BUFFER_SIZE - 1) || leftToSend == 0)
        {
            unsigned int aConnections = 1;

            // Find how many connections are open from one IP address
            // This is a critical section
            if (isIPv4)
            {
                aConnectionsIPv4 thisConnection;

                dequeMutex.lock();
                thisConnection = findIPv4Connection(clientAddress);
                aConnections = thisConnection.opConnections;
                dequeMutex.unlock();
            }
            else
            {
                aConnectionsIPv6 thisConnection;

                dequeMutex.lock();
                thisConnection = findIPv6Connection(clientAddress);
                aConnections = thisConnection.opConnections;
                dequeMutex.unlock();
            }

            // The speed of transfer is determined by how long the thread will sleep 
            //Sleep(THREAD_SLEEP / aConnections);

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

    // Find this connection in deque and remove it (or decrement opConnections counter)
    unsigned int connectionIndex = 0;

    if (isIPv4)
    {
        aConnectionsIPv4 thisConnection;

        dequeMutex.lock();
        connectionIndex = findIPv4ConnectionIndex(clientAddress);
        
        // Check if there is more than one connection from the same IP address
        if (IPv4Connections[connectionIndex].opConnections < 2)
        {
            IPv4Connections.erase(IPv4Connections.begin() + connectionIndex);
        }
        else
        {
            IPv4Connections[connectionIndex].opConnections--;
        }

        dequeMutex.unlock();
    }
    else
    {
        aConnectionsIPv6 thisConnection;

        dequeMutex.lock();
        connectionIndex = findIPv6ConnectionIndex(clientAddress);
        
        // Check if there is more than one connection from the same IP address
        if (IPv6Connections[connectionIndex].opConnections < 2)
        {
            IPv6Connections.erase(IPv6Connections.begin() + connectionIndex);
        }
        else
        {
            IPv6Connections[connectionIndex].opConnections--;
        }

        dequeMutex.unlock();
    }


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
        char ipAddress1[IPv4_ADDR_LEN]; // 15 spaces for decimal notation (for example: "192.168.100.200") + '\0'
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

int addConnection (sockaddr_in6 clientAddress)
{
    char ipAddress[INET6_ADDRSTRLEN]; // INET6_ADDRSTRLEN 65 spaces for hexadecimal notation of IPv6

    // Copy client ip to local char[]
    inet_ntop(clientAddress.sin6_family, &clientAddress.sin6_addr, ipAddress, sizeof(ipAddress));

    bool isIPv4 = is_ipV4_address(clientAddress); //true for IPv4 and false for IPv6

    if (isIPv4)
    {
        char ipAddress1[IPv4_ADDR_LEN]; // 15 spaces for decimal notation (for example: "192.168.100.200") + '\0'
        struct in_addr *ipv4 = (struct in_addr*)&((char*)&clientAddress.sin6_addr.u)[12];

        // Copy client ip to local char[]
        strcpy_s(ipAddress1, sizeof(ipAddress1), inet_ntoa(*ipv4));

        if (IPv4Connections.empty())
        {
            // Copy client ip to new connection
            aConnectionsIPv4 connectionIPv4;

            strcpy_s(connectionIPv4.clientAddress, sizeof(connectionIPv4.clientAddress), ipAddress1);
            connectionIPv4.opConnections = 1;

            // Add new connection do deque
            IPv4Connections.push_front(connectionIPv4);

            return 0;
        }

        // Iterate trough connections and add new one or update existing
        std::deque<aConnectionsIPv4>::iterator it;

        for (it = IPv4Connections.begin(); it != IPv4Connections.end(); it++)
        {
            if (!(strcmp((*it).clientAddress, ipAddress1)))
            {
                (*it).opConnections++;
                return 0;
            }
        }
        
        // Copy client ip to new connection
        aConnectionsIPv4 connectionIPv4;

        strcpy_s(connectionIPv4.clientAddress, sizeof(connectionIPv4.clientAddress), ipAddress1);
        connectionIPv4.opConnections = 1;

        // Add new connection do deque
        IPv4Connections.push_front(connectionIPv4);

        return 0;
    }
    else
    {
        if (IPv6Connections.empty())
        {
            // Copy client ip to new connection
            aConnectionsIPv6 connectionIPv6;

            strcpy_s(connectionIPv6.clientAddress, sizeof(connectionIPv6.clientAddress), ipAddress);
            connectionIPv6.opConnections = 1;

            // Add new connection do deque
            IPv6Connections.push_front(connectionIPv6);

            return 0;
        }

        // Iterate trough connections and add new one or update existing
        std::deque<aConnectionsIPv6>::iterator it;

        for (it = IPv6Connections.begin(); it != IPv6Connections.end(); it++)
        {
            if (!(strcmp((*it).clientAddress, ipAddress)))
            {
                (*it).opConnections++;
                return 0;
            }
        }

        // Copy client ip to new connection
        aConnectionsIPv6 connectionIPv6;

        strcpy_s(connectionIPv6.clientAddress, sizeof(connectionIPv6.clientAddress), ipAddress);
        connectionIPv6.opConnections = 1;

        // Add new connection do deque
        IPv6Connections.push_front(connectionIPv6);

        return 0;
    }

    return 1;
}

aConnectionsIPv4 findIPv4Connection (sockaddr_in6 clientAddress)
{
    char ipAddress1[IPv4_ADDR_LEN]; // 15 spaces for decimal notation (for example: "192.168.100.200") + '\0'
    struct in_addr *ipv4 = (struct in_addr*)&((char*)&clientAddress.sin6_addr.u)[12];

    // Copy client ip to local char[]
    strcpy_s(ipAddress1, sizeof(ipAddress1), inet_ntoa(*ipv4));

    std::deque<aConnectionsIPv4>::iterator it;

    for (it = IPv4Connections.begin(); it != IPv4Connections.end(); it++)
    {
        if (!(strcmp((*it).clientAddress, ipAddress1)))
        {
            return *it;
        }
    }
}

aConnectionsIPv6 findIPv6Connection(sockaddr_in6 clientAddress)
{
    char ipAddress[INET6_ADDRSTRLEN]; // INET6_ADDRSTRLEN 65 spaces for hexadecimal notation of IPv6

    // Copy client ip to local char[]
    inet_ntop(clientAddress.sin6_family, &clientAddress.sin6_addr, ipAddress, sizeof(ipAddress));

    std::deque<aConnectionsIPv6>::iterator it;

    for (it = IPv6Connections.begin(); it != IPv6Connections.end(); it++)
    {
        if (!(strcmp((*it).clientAddress, ipAddress)))
        {
            return *it;
        }
    }
}

unsigned int findIPv4ConnectionIndex (sockaddr_in6 clientAddress)
{
    char ipAddress1[IPv4_ADDR_LEN]; // 15 spaces for decimal notation (for example: "192.168.100.200") + '\0'
    struct in_addr *ipv4 = (struct in_addr*)&((char*)&clientAddress.sin6_addr.u)[12];

    // Copy client ip to local char[]
    strcpy_s(ipAddress1, sizeof(ipAddress1), inet_ntoa(*ipv4));

    std::deque<aConnectionsIPv4>::iterator it;

    for (it = IPv4Connections.begin(); it != IPv4Connections.end(); it++)
    {
        if (!(strcmp((*it).clientAddress, ipAddress1)))
        {
            int index = std::distance(IPv4Connections.begin(), it);
            return index;
        }
    }
    return -1;
}

unsigned int findIPv6ConnectionIndex (sockaddr_in6 clientAddress)
{
    char ipAddress[INET6_ADDRSTRLEN]; // INET6_ADDRSTRLEN 65 spaces for hexadecimal notation of IPv6

                                      // Copy client ip to local char[]
    inet_ntop(clientAddress.sin6_family, &clientAddress.sin6_addr, ipAddress, sizeof(ipAddress));

    std::deque<aConnectionsIPv6>::iterator it;

    for (it = IPv6Connections.begin(); it != IPv6Connections.end(); it++)
    {
        if (!(strcmp((*it).clientAddress, ipAddress)))
        {
            int index = std::distance(IPv6Connections.begin(), it);
            return index;
        }
    }
    return -1;
}