// TODO(louis):
// 	- compute the hash for common headers we have to check at compile time
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "http_header_map.h"
#include "arena_allocator.h"
#include "types.h"
#include "http.h"

u16 MAX_N_PENDING_CONNECTIONS = 128;

i32 socketDescriptor = -1;
i32 clientSocketDescriptor = -1;

void signalHandler(i32 signalId)
{
	if (signalId == SIGINT)
	{
		if (clientSocketDescriptor >= 0)
		{
			close(clientSocketDescriptor);
			clientSocketDescriptor = -1;
		}

		if (socketDescriptor >= 0)
		{
			close(socketDescriptor);
			socketDescriptor = -1;
		}
	}
}

http_status_code handleGetRequest(http_header* header)
{
	return OK;
}

http_status_code handlePostRequest(http_header* httpHeader, u8* messageBodyStartPtr, u8* messageBodyEndPtr)
{
	string transferCoding;
	string contentLength;
	i16 hasTransferCoding = getHash(&transferCoding, &httpHeader->headerMap, 
								 	TRANSFER_ENCODING_HASH, (string*) &TRANSFER_ENCODING_STRING);
	i16 hasContentLength = getHash(&contentLength, &httpHeader->headerMap, 
								   CONTENT_LENGTH_HASH, (string*) &CONTENT_LENGTH_STRING);

	if (hasTransferCoding && hasContentLength)
		// TODO(louis): send some response
		return BAD_REQUEST;

	// else if (hasTransferCoding)
	// {
	// }
	// else if (hasContentLength)
	// {
	// }
	// else
	// {
	// }

	return OK;
}

i16 serve(u16 port)
{ 
	arena_allocator arena;
	if (init(&arena, 1024 * 1024) == -1)
		return -1;

	socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
	if (socketDescriptor == -1)
		return -1;

	struct sockaddr_in socketAddr;
	if (!inet_pton(AF_INET, "0.0.0.0", &socketAddr.sin_addr))
		goto close_server_socket;

	socketAddr.sin_family = AF_INET;
	socketAddr.sin_port = htons(port);

	if (bind(socketDescriptor, 
		 	 (struct sockaddr*) &socketAddr, 
		  	 sizeof(socketAddr)) == -1)
		goto close_server_socket;

	if (listen(socketDescriptor, MAX_N_PENDING_CONNECTIONS) == -1)
		goto close_server_socket;

	http_header httpHeader;
	// TODO(louis): move this into a constant
	if (init(&httpHeader.headerMap, &arena, 128) == -1)
		goto close_server_socket;

	for (;;)
	{
		// TODO(louis): spawn multiple threads that can accept and handle connections.
		struct sockaddr_in clientSocketAddr;
		socklen_t addrlen;
		
		clientSocketDescriptor = accept(socketDescriptor, (struct sockaddr*) &clientSocketAddr, &addrlen);
		if (clientSocketDescriptor == -1)
		{
			// TODO(louis): Implement some proper error handling (see man page).
			goto close_server_socket;
		}

		// TODO(louis): maybe only read if poll returns a positive number (something is there to read). 
		// This might help handling multiple connections on one thread.
		
		u8 buffer[MAX_HTTP_HEADER_SIZE];
		for (;;)
		{
			i32 readBytes = read(clientSocketDescriptor, buffer, sizeof(buffer));	
			if (readBytes <= 0)
				goto close_client_socket;

			u16 errorCode;
			u8* messageBodyStartPtr = parseHeader(&errorCode, &httpHeader, buffer, readBytes);
			if (messageBodyStartPtr == (u8*) -1)
			{
				// TODO(louis): replace this with the actual error code
				const u8* corruptedHeaderResponse = lookupResponse(BAD_REQUEST);
				write(clientSocketDescriptor, (void*) corruptedHeaderResponse, DEFAULT_RESPONSE_LEN);
				goto close_client_socket;
			}

			string hostHeaderField;
			if (!getHash(&hostHeaderField, &httpHeader.headerMap, 
						 HOST_HEADER_HASH, (string*) &HOST_STRING))
			{
				const u8* missingHostHeaderResponse = lookupResponse(BAD_REQUEST);
				write(clientSocketDescriptor, (void*) missingHostHeaderResponse, DEFAULT_RESPONSE_LEN);
				goto close_client_socket;
			}

			switch (httpHeader.method)
			{
				case GET:
				{
					http_status_code statusCode = handleGetRequest(&httpHeader);
					const u8* response = lookupResponse(statusCode);
					i16 res = write(clientSocketDescriptor, (void*) response, DEFAULT_RESPONSE_LEN);
					break;
				}
				case POST:
				{
					http_status_code statusCode = handlePostRequest(&httpHeader, messageBodyStartPtr, buffer + readBytes);
					const u8* response = lookupResponse(statusCode);
					i16 res = write(clientSocketDescriptor, (void*) response, DEFAULT_RESPONSE_LEN);
					break;
				}
			}
		}

	close_client_socket:
		clear(&httpHeader.headerMap);
		if (clientSocketDescriptor >= 0)
		{
			if (close(clientSocketDescriptor) == -1)
				goto close_server_socket;
		}
	}

close_server_socket:
	// TODO(louis): make sure that we really call munmap on SIGINT
	destroy(&arena);
	if (socketDescriptor >= 0)
	{
		close(socketDescriptor);
		return -1;
	}

	return 0;
}

i32 main(i32 argc, char** argv)
{
	if (signal(SIGINT, signalHandler) == SIG_ERR) 
	{
		fprintf(stderr, "Error while setting signal handler: %d\n", errno);
		return -1;
	}

	if (serve(8080) == -1)
	{
		fprintf(stderr, "Got some error: %d\n", errno);
		return -1;
	}

	return 0;
}
