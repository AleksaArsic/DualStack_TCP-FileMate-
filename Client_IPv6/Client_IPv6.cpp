// TCP client that uses blocking sockets

#define WIN32_LEAN_AND_MEAN

#include <stdlib.h>
#include <stdio.h>
#include "Client_IPv6.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

int main()
{
    // File names in folder recieved
    std::deque<const char*> fileNames;

    // Indicates of how much parts data consists
    int noOfFiles = 0;

    // Part of file to receive
    int partToRecv = 0;

    // Server address structure
    sockaddr_in6 serverAddress;

    // Size of server address structure
	int sockAddrLen = sizeof(serverAddress);

	// Buffer that will be used for sending and receiving messages to client
    char dataBuffer[BUFFER_SIZE];

	// WSADATA data structure that is used to receive details of the Windows Sockets implementation
    WSADATA wsaData;
    
    printf("%s\n\n", CLIENT_DESC);

	// Initialize windows sockets for this process
	int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    
	// Check if library is succesfully initialized
	if (iResult != 0)
    {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    // Create a socket
    SOCKET clientSocket = socket(AF_INET6,      // IPv6 address famly
        SOCK_STREAM,   // Stream socket
        IPPROTO_TCP); // TCP protocol

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
	serverAddress.sin6_family = AF_INET6;								// IPv6 address famly
    inet_pton(AF_INET6, SERVER_IP_ADDRESS, &serverAddress.sin6_addr);	// Set server IP address using string
    serverAddress.sin6_port = htons(SERVER_PORT);						// Set server port
	serverAddress.sin6_flowinfo = 0;									// flow info
	 
    //Connect to remote server
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
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
        printf("[*] Connection accepted.\n");
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
        printf("[*] %s\n", SERVER_READY);
        printf("[*] Data you are trying to download consists of: %s files.\n\n", dataBuffer);

        noOfFiles = dataBuffer[0] - '0';
    }

    // Set whole buffer to zero
    memset(outputFileName, 0, NAME_BUF_SIZE);
 
    do {
        printf("Enter part of the file to recieve: ");
        scanf("%d", &partToRecv);
        printf("\n");
    } while (partToRecv > noOfFiles || partToRecv <= 0);

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

    fileNameGen(outputFileName, partToRecv);

    /* RECEIVE CHUNKS OF DATA */

    // Set whole buffer to zero
    memset(dataBuffer, 0, BUFFER_SIZE);

    FILE* filePtr;

    // Remove file if existing in received\\ directory 
    removeFile(outputFileName);

    filePtr = fopen(outputFileName, "w");

    printf("\nDownloading...\n");

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

            while ((iResult--) > 0)
            {
                fprintf(filePtr, "%c", dataBuffer[i++]);

            }
        }

    }while (isEOF);

    fclose(filePtr);

    printf("\n[*] Download complete.\n");

	// Close client application
    iResult = closesocket(clientSocket);
    if (iResult == SOCKET_ERROR)
    {
        printf("closesocket failed with error: %d\n", WSAGetLastError());
		WSACleanup();
        return 1;
    }

    // Merge files if all parts of data are received
    fileNames = getFileNamesFromFolder(FILE_FOLDER);

    if (fileNames.size() == noOfFiles)
    {
        printf("[*] Merging downloaded files...\n\n");

        bool isMerged = mergeFiles(fileNames);

        if (isMerged)
        {
            printf("\n[*] Downloading and Merging completed.\n");
        }
        else
        {
            printf("\n[*] Merging failed.\n");
            return 1;
        }
    }

    // Only for demonstration purpose
    printf("\nPress any key to exit: ");
    _getch();

    // Clear deque
    fileNames.clear();

	// Close Winsock library
    WSACleanup();

	// Client has succesfully sent a message
    return 0;
}

void removeFile(const char* fileName)
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

std::deque<const char*> getFileNamesFromFolder(const char* folder)
{
    WIN32_FIND_DATAA FindFileData;
    HANDLE hFind;

    std::deque<const char*> fileNames;

    hFind = FindFirstFileA(folder, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        printf("FindFirstFile failed (%d)\n", GetLastError());
    }
    else
    {
        do
        {
            char* name = (char*)malloc(strlen(FindFileData.cFileName) * sizeof(char));
            strcpy(name, FindFileData.cFileName);

            fileNames.push_back(name);

        } while (FindNextFileA(hFind, &FindFileData) != 0);

        FindClose(hFind);
    }

    return fileNames;
}

bool mergeFiles(std::deque<const char*> fileNames)
{
    FILE* outputFilePtr;
    std::deque<const char*>::iterator it;

    removeFile(DOWN_NAME);

    // Open output file
    outputFilePtr = fopen(DOWN_NAME, "a");

    for (it = fileNames.begin(); it != fileNames.end(); it++)
    {
        char* fileName = (char*)malloc(strlen(*it) * sizeof(char) + 10);

        strcpy(fileName, "received\\");
        strcat(fileName, *it);

        FILE* filePtr = fopen(fileName, "r");
        char cFromFile;

        while ((cFromFile = fgetc(filePtr)) != EOF)
        {
            fputc(cFromFile, outputFilePtr);
            //printf("%c", cFromFile);
        }


        fclose(filePtr);

    }

    fclose(outputFilePtr);

    return true;
}