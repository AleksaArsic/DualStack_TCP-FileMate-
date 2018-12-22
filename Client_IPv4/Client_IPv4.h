#pragma once

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "conio.h"
#include <deque>
#include <iterator>

#define CLIENT_DESC "FileMate Client - a simple file sharing application" // Description of application

#define SERVER_IP_ADDRESS "127.0.0.1"	  // IPv4 address of server
#define SERVER_PORT 27015			      // Port number of server that will be used for communication with clients
#define BUFFER_SIZE 512				      // Size of buffer that will be used for sending and receiving messages to client
#define NAME_BUF_SIZE 26                  // Size of file name buffer

#define SERVER_READY "Server ready for transfer." // Indicates that server is ready for file transfer

#define FILE_NAME "received\\output.dat"    // Location and name of file for receiveing
#define FILE_FOLDER "received\\output.*"            // Folder to search for files
#define DOWN_NAME "received\\downloaded.dat" // Downloaded data

// Removes output file from received folder
void removeFile(const char* fileName);
// Generates file name
void fileNameGen(char* fileName, int partToRecv);
// Return names of the files in folder
std::deque<const char*> getFileNamesFromFolder(const char* folder);
// Merge received files
bool mergeFiles(std::deque<const char*> fileNames);

// Name of the file
char outputFileName[NAME_BUF_SIZE];

