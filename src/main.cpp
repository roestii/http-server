// TODO(louis):
// 	- compute the hash for common headers we have to check at compile time
// 	- introduce proper error handling using the rfc

#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>

#include "http_header_map.h"
#include "arena_allocator.h"
#include "file_cache.h"
#include "types.h"
#include "string.h"
#include "http.h"

constexpr u16 MAX_N_PENDING_CONNECTIONS = 128;
constexpr usize MEMORY_LIMIT = 10 * 1024 * 1024;
constexpr usize FILE_CACHE_LIMIT = 8 * 1024 * 1024;

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

i16 writeResponse(i32 fd, http_response* response)
{
	FILE* socketStream = fdopen(fd, "w");
	if (!socketStream)
		return -1;
	
	const char* statusLine = lookupStatusLine(response->statusCode);
	if (fputs(statusLine, socketStream) == EOF)
		return -1;

	char* reason = response->reason;
	if (reason && fputs(reason, socketStream) == EOF)
		return -1;

	if (fwrite((void*) CRLF, sizeof(char), CRLF_LEN, socketStream) != CRLF_LEN)
		return -1;

	// TODO(louis): consider making this a list in the future
	// and consider moving away from fwrite and rather handling this on your own
	http_header_map headerMap = response->headerMap;
	http_header_bucket* currentBucket = headerMap.buckets;
	for (int i = 0; i < HASH_TABLE_M; ++i, ++currentBucket)
	{
		if (currentBucket->tag != INITIALIZED)
			continue;

		string fieldName = currentBucket->fieldName;
		string fieldValue = currentBucket->fieldValue;
		if (fwrite((void*) fieldName.ptr, sizeof(char), 
			 		fieldName.len, socketStream) != fieldName.len)
			return -1;
		if (fputc(':', socketStream) != ':')
			return -1;
		if (fwrite((void*) fieldValue.ptr, sizeof(char), fieldValue.len, socketStream) != fieldValue.len)
			return -1;
		if (fwrite((void*) CRLF, sizeof(char), CRLF_LEN, socketStream) != CRLF_LEN)
			return -1;
	}

	if (fwrite((void*) CRLF, sizeof(char), CRLF_LEN, socketStream) != CRLF_LEN)
		return -1;

	string messageBody = response->messageBody;
	if (messageBody.ptr)
	{
		if (fwrite((void*) messageBody.ptr, sizeof(char), 
			 		messageBody.len, socketStream) != messageBody.len)
			return -1;
	}
	
	if (fclose(socketStream) == EOF)
		return -1;

	return 0;
}

void handleGetRequest(http_response* result, http_request* request, 
					  file_cache* fileCache, arena_allocator* alloc)
{
	file_handle_entry fileHandle;
	// TODO(louis): Make sure that this is actually safe
	request->requestTarget.ptr++;
	request->requestTarget.len--;
	if (get(&fileHandle, fileCache, &request->requestTarget))
	{
		result->statusCode = OK;
		result->reason = NULL;
		result->messageBody = 
		{ 
			fileHandle.contentHandle, 
			(isize) fileHandle.fileSize 
		};
		string contentLengthValue;
		u64ToStr(&contentLengthValue, alloc, fileHandle.fileSize);
		insert(&result->headerMap, (string*) &CONTENT_LENGTH_STRING, &contentLengthValue);
	}
	else
	{
		// TODO(louis): figure out the appropriate stats code
		result->statusCode = NOT_FOUND;
		result->reason = NULL;
		result->messageBody = {0};
	}
}

void handlePostRequest(http_response* result, http_request* request, arena_allocator* alloc)
{
	string transferCoding;
	string contentLength;
	i16 hasTransferCoding = getHash(&transferCoding, &request->headerMap, 
								 	TRANSFER_ENCODING_HASH, (string*) &TRANSFER_ENCODING_STRING);
	i16 hasContentLength = getHash(&contentLength, &request->headerMap, 
								   CONTENT_LENGTH_HASH, (string*) &CONTENT_LENGTH_STRING);

	if (hasTransferCoding && hasContentLength)
	{
		// TODO(louis): send some response
		// The version and the header map should already be initialized.
		result->statusCode = BAD_REQUEST;
		result->reason = NULL;
		result->messageBody = {0};
	}
	else if (hasTransferCoding)
	{
		result->statusCode = BAD_REQUEST;
		result->reason = NULL;
		result->messageBody = {0};
	}
	else if (hasContentLength)
	{
		string messageBody = request->messageBody;
		// u32 contentLengthInt = stringToU32(&contentLength);
		// if (contentLengthInt > messageBody.len)
		// {
		// 	result->statusCode = BAD_REQUEST;
		// 	result->reason = NULL;
		// 	return;
		// }
		
		result->statusCode = OK;
		result->reason = NULL;
		result->messageBody = {0};
		insert(&result->headerMap, (string*) &CONTENT_LENGTH_STRING, (string*) &ZERO_LEN_STRING);
	}
	else
	{
		result->statusCode = BAD_REQUEST;
		result->reason = NULL;
		result->messageBody = {0};
	}
}

i16 serve(u16 port)
{ 
	arena_allocator programMemory;
	if (init(&programMemory, MEMORY_LIMIT) == -1)
		return -1;

	arena_allocator requestLocalMemory;
	if (subarena(&requestLocalMemory, &programMemory, MEMORY_LIMIT - FILE_CACHE_LIMIT) == -1)
		return -1;

	arena_allocator fileCacheMemory;
	if (subarena(&fileCacheMemory, &programMemory, FILE_CACHE_LIMIT) == -1)
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

	http_request request;
	init(&request.headerMap);
	
	file_cache fileCache;
	if (buildStaticCache(&fileCache, &fileCacheMemory) == -1)
		return -1;

	for (;;)
	{
		// TODO(louis): spawn multiple threads that can accept and handle connections.
		struct sockaddr_in clientSocketAddr;
		socklen_t addrlen;
		
		clientSocketDescriptor = accept(socketDescriptor, (struct sockaddr*) &clientSocketAddr, &addrlen);
		if (clientSocketDescriptor == -1)
			// TODO(louis): Implement some proper error handling (see man page).
			goto close_server_socket;

		// TODO(louis): maybe only read if poll returns a positive number (something is there to read). 
		// This might help handling multiple connections on one thread.
		
		char buffer[MAX_HTTP_HEADER_SIZE];
		http_response response;
		init(&response.headerMap);

		for (;;)
		{
			i32 readBytes = read(clientSocketDescriptor, buffer, MAX_HTTP_HEADER_SIZE);	
			if (readBytes <= 0)
				goto close_client_socket;

			u16 errorCode;
			if (parseHttpRequest(&errorCode, &request, buffer, readBytes) == CORRUPTED_HEADER)
			{
				// TODO(louis): replace this with the actual error code
				const char* corruptedHeaderResponse = lookupStatusLine(BAD_REQUEST);
				write(clientSocketDescriptor, (void*) corruptedHeaderResponse, DEFAULT_RESPONSE_LEN);
				goto close_client_socket;
			}

			string hostHeaderField;
			if (!getHash(&hostHeaderField, &request.headerMap, 
						 HOST_HEADER_HASH, (string*) &HOST_STRING))
			{
				const char* missingHostHeaderResponse = lookupStatusLine(BAD_REQUEST);
				write(clientSocketDescriptor, (void*) missingHostHeaderResponse, DEFAULT_RESPONSE_LEN);
				goto close_client_socket;
			}

			switch (request.method)
			{
				case GET:
				{
					handleGetRequest(&response, &request, &fileCache, &requestLocalMemory);
	   				if (writeResponse(clientSocketDescriptor, &response) == -1)
						goto close_client_socket;

					break;
				}
				case POST:
				{
					handlePostRequest(&response, &request, &requestLocalMemory);
	   				if (writeResponse(clientSocketDescriptor, &response) == -1)
						goto close_client_socket;

					break;
				}
			}
		}

	close_client_socket:
		reset(&requestLocalMemory);
		clear(&request.headerMap);
		clear(&response.headerMap);

		if (clientSocketDescriptor >= 0) 
			close(clientSocketDescriptor);
	}

close_server_socket:
	// TODO(louis): make sure that we really call munmap on SIGINT
	// and make sure to close all client connections
	destroy(&programMemory);
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
