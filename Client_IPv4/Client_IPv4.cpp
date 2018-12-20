// TCP client that uses blocking sockets

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

#define SERVER_IP_ADDRESS "127.0.0.1"		// IPv4 address of server
#define SERVER_PORT 27015					// Port number of server that will be used for communication with clients
#define BUFFER_SIZE 512						// Size of buffer that will be used for sending and receiving messages to client
#define NAME_BUF_SIZE 26                   // Size of file name buffer

#define FILE_NAME "received\\output.dat" // location and name of file for receiveing

// Removes output file from received folder
void removeFile();
// Generates file name
void fileNameGen(char* fileName, int partToRecv);

// Name of the file
char fileName[NAME_BUF_SIZE];

int main()
{
    // Server address structure
    sockaddr_in serverAddress;

    // Size of server address structure
	int sockAddrLen = sizeof(serverAddress);

	// Buffer that will be used for sending and receiving messages to client
    char dataBuffer[BUFFER_SIZE];

	// WSADATA data structure that is used to receive details of the Windows Sockets implementation
    WSADATA wsaData;
    
	// Initialize windows sockets for this process
	int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    
	// Check if library is succesfully initialized
	if (iResult != 0)
    {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    SOCKET clientSocket = socket(AF_INET,      // IPv4 address family
        SOCK_STREAM,   // Stream socket
        IPPROTO_TCP);  // TCP Protocol

                       // Check if socket creation succeeded
    if (clientSocket == INVALID_SOCKET)
    {
        printf("Creating socket failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }


   // Initialize memory for address structure
    memset((char*)&serverAddress, 0, sizeof(serverAddress));		
    
	// Initialize address structure of server
	serverAddress.sin_family = AF_INET;								// IPv4 address famly
    serverAddress.sin_addr.s_addr = inet_addr(SERVER_IP_ADDRESS);	// Set server IP address using string
    serverAddress.sin_port = htons(SERVER_PORT);					// Set server port

    //Connect to remote server
    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)
    {
        perror("connect failed. Error");
        return 1;
    }
    puts("Connected to remote server.\n");


    listen(clientSocket, SOMAXCONN); // Listen on serverSocket, maximum queue is a reasonable number

                                     // Declare and initialize client address that will be set from recvfrom
    sockaddr_in6 clientAddress;
    memset(&clientAddress, 0, sizeof(clientAddress));

    // size of client address
    sockAddrLen = sizeof(clientAddress);

    SOCKET serverSocket = accept(clientSocket, (struct sockaddr *)&clientAddress, (socklen_t*)&sockAddrLen);

    printf("SERVER:\n");

    if (clientSocket < 0) {
        perror("accept failed");
        return 1;
    }
    else {
        printf("Connection accepted.\n");
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
    else
    {
        printf("%s\n\n", dataBuffer);
    }

    // Part of file to receive
    int partToRecv = 0;

    // Set whole buffer to zero
    memset(fileName, 0, NAME_BUF_SIZE);

    printf("Enter part of the file to recieve: ");
    scanf("%d", &partToRecv);

    // Set whole buffer to zero
    memset(dataBuffer, 0, BUFFER_SIZE);

    dataBuffer[0] = partToRecv + '0';

    // Send message to server
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
        return 1;
    }

    fileNameGen(fileName, partToRecv);

    printf("Filename: %s\n", fileName);

    /* RECEIVE CHUNKS OF DATA */

    // Set whole buffer to zero
    memset(dataBuffer, 0, BUFFER_SIZE);

    FILE* filePtr;

    // Remove file if existing in received\\ directory 
    removeFile();

    filePtr = fopen(fileName, "w");

    int isEOF = 0;
    do {
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

        // Write to file 
        isEOF = strcmp(dataBuffer, "EOF\0");

        if (isEOF != 0)
        {
            int i = 0;

            while ( (iResult--) > 0)
            {
                fprintf(filePtr, "%c", dataBuffer[i++]);

            }
        }

    }while (isEOF);

    fclose(filePtr); 

	// Only for demonstration purpose
	printf("Press any key to exit: ");
	_getch();

	// Close client application
    iResult = closesocket(clientSocket);
    if (iResult == SOCKET_ERROR)
    {
        printf("closesocket failed with error: %d\n", WSAGetLastError());
		WSACleanup();
        return 1;
    }

	// Close Winsock library
    WSACleanup();

	// Client has succesfully sent a message
    return 0;
}

void removeFile ()
{
    int status = remove(fileName);

    if (status == 0)
        printf("%s file deleted successfully.\n", fileName);
    else
    {
        printf("Unable to delete the file\n");
        perror("Following error occurred");
    }
}

void fileNameGen(char* fileName, int partToRecv)
{
    strcpy(fileName, FILE_NAME);

    const char partBuff[5] = { '.', 'p', 'a', 'r', 't' };

    const char partToRecvC = partToRecv + '0';

    strcat(fileName, partBuff);
    fileName[24] = partToRecv + '0';
    fileName[25] = 0;
}