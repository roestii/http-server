// TODO(louis):
// 	- introduce proper error handling using the rfc
// 	- fix the server closing (this may be fixed)
// 	- implement some transfer encoding, for the response maybe... (but this might not actually be worth it)
// 	- make the server multithreaded
// 	- parsing of the request target
// 	- obsolete line folding
// 	- what if the Content-Length + the header size exceeds 8000 bytes. should we just return message too large?

#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <netdb.h>
#include <pthread.h>

#include "http_header_map.h"
#include "arena_allocator.h"
#include "file_cache.h"
#include "types.h"
#include "string.h"
#include "http.h"

constexpr u8 N_THREADS = 8;
constexpr u16 MAX_N_PENDING_CONNECTIONS = 128;
constexpr u16 PORT = 8080;

constexpr usize MEMORY_LIMIT = 10 * 1024 * 1024;
constexpr usize FILE_CACHE_LIMIT = 8 * 1024 * 1024;
constexpr usize THREAD_LOCAL_MEMORY = (MEMORY_LIMIT - FILE_CACHE_LIMIT) / N_THREADS;

pthread_mutex_t killMutex;
pthread_cond_t killSignal;

void signalHandler(i32 signalId)
{
	if (signalId == SIGINT)
	{
		if (pthread_mutex_lock(&killMutex) != 0)
			return;
		if (pthread_cond_signal(&killSignal) != 0)
			return;
		if (pthread_mutex_unlock(&killMutex) != 0)
			return;
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
		initEmptyResponse(result, NOT_FOUND);
}

void handlePostRequest(http_response* result, http_request* request, arena_allocator* alloc)
{
	// NOTE(louis): the caller has to ensure that the headerMap of the result was initialized.
	string transferCoding;
	string contentLength;
	i16 hasTransferCoding = getHash(&transferCoding, &request->headerMap, 
								 	TRANSFER_ENCODING_HASH, (string*) &TRANSFER_ENCODING_STRING);
	i16 hasContentLength = getHash(&contentLength, &request->headerMap, 
								   CONTENT_LENGTH_HASH, (string*) &CONTENT_LENGTH_STRING);

	if (hasTransferCoding && hasContentLength)
		// TODO(louis): send some response
		// The version and the header map should already be initialized.
		initEmptyResponse(result, BAD_REQUEST);
	else if (hasTransferCoding)
		initEmptyResponse(result, NOT_IMPLEMENTED);
	else if (hasContentLength)
	{
		string messageBody = request->messageBody;
		u64 contentLengthInt;
		if (strToU64(&contentLengthInt, &contentLength) == -1)
		{
			initEmptyResponse(result, BAD_REQUEST);
			return;
		}

		if (contentLengthInt > messageBody.len)
		{
			initEmptyResponse(result, TOO_LARGE);
			return;
		}
		
		initEmptyResponse(result, OK);
		insert(&result->headerMap, (string*) &CONTENT_LENGTH_STRING, (string*) &ZERO_LEN_STRING);
	}
	else
		initEmptyResponse(result, BAD_REQUEST);
}

struct handle_request_args 
{
	file_cache* fileCache;
	arena_allocator* requestLocalMemory;
	i32 socketDescriptor;
};

void* handleRequests(void* args)
{
	handle_request_args* handleRequestArgs = (handle_request_args*) args;
	file_cache* fileCache = handleRequestArgs->fileCache;
	arena_allocator* requestLocalMemory = handleRequestArgs->requestLocalMemory;
	i32 socketDescriptor = handleRequestArgs->socketDescriptor;

	http_request request;
	http_response response;
	init(&request.headerMap);
	init(&response.headerMap);

	for (;;)
	{
		// TODO(louis): spawn multiple threads that can accept and handle connections.
		struct sockaddr_in clientSocketAddr;
		socklen_t addrlen;
		
		i32 clientSocketDescriptor = accept(socketDescriptor, (struct sockaddr*) &clientSocketAddr, &addrlen);
		if (clientSocketDescriptor == -1)
			// TODO(louis): Implement some proper error handling (see man page).
			continue;

		char buffer[MAX_HTTP_MESSAGE_LEN];
		i32 readBytes = read(clientSocketDescriptor, buffer, MAX_HTTP_HEADER_LEN);	
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

		if (readBytes == MAX_HTTP_HEADER_LEN)
		{
			i32 n = read(clientSocketDescriptor, buffer + MAX_HTTP_HEADER_LEN, 
						 MAX_HTTP_MESSAGE_LEN - MAX_HTTP_HEADER_LEN);
			
			if (n > 0)
			{
				if (request.messageBody.ptr)
					request.messageBody.len += n;
				else
				{
	  				request.messageBody = 
					{
						buffer + MAX_HTTP_HEADER_LEN,
						n
					};
				}
			}
		}

		switch (request.method)
		{
			case GET:
			{
				handleGetRequest(&response, &request, fileCache, requestLocalMemory);
				if (writeResponse(clientSocketDescriptor, &response) == -1)
					goto close_client_socket;

				break;
			}
			case POST:
			{
				handlePostRequest(&response, &request, requestLocalMemory);
				if (writeResponse(clientSocketDescriptor, &response) == -1)
					goto close_client_socket;

				break;
			}
		}

	close_client_socket:
		reset(requestLocalMemory);
		clear(&request.headerMap);
		clear(&response.headerMap);

		if (clientSocketDescriptor >= 0) 
			close(clientSocketDescriptor);
	}
}

i16 serve(u16 port)
{ 
	i16 retval = 0;
	struct protoent* tcpProto = getprotobyname("tcp");
	if(!tcpProto)
		return -1;

	arena_allocator programMemory;
	if (init(&programMemory, MEMORY_LIMIT) == -1)
		return -1;

	arena_allocator fileCacheMemory;
	if (subarena(&fileCacheMemory, &programMemory, FILE_CACHE_LIMIT) == -1)
		return -1;

	i32 socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
	if (socketDescriptor == -1)
		return -1;

	i32 optval = 1;
	struct sockaddr_in socketAddr;
	if (!inet_pton(AF_INET, "0.0.0.0", &socketAddr.sin_addr))
	{
		retval = -1;
		goto server_clean_up;
	}

	socketAddr.sin_family = AF_INET;
	socketAddr.sin_port = htons(port);

#if DEBUG_MODE 
	if (setsockopt(socketDescriptor, SOL_SOCKET, 
			   	   SO_REUSEADDR, &optval, sizeof(optval)) == -1)
	{
		retval = -1;
		goto server_clean_up;
	}
#endif

	if (bind(socketDescriptor, 
		 	 (struct sockaddr*) &socketAddr, 
		  	 sizeof(socketAddr)) == -1)
	{
		retval = -1;
		goto server_clean_up;
	}

	if (listen(socketDescriptor, MAX_N_PENDING_CONNECTIONS) == -1)
	{
		retval = -1;
		goto server_clean_up;
	}

	{
		file_cache fileCache;
		if (buildStaticCache(&fileCache, &fileCacheMemory) == -1)
		{
			retval = -1;
			goto server_clean_up;
		}

		pthread_t threadHandles[N_THREADS];
		arena_allocator requestLocalMemory[N_THREADS];
		handle_request_args workerArgs[N_THREADS];

		pthread_t* currentThreadHandle = threadHandles;
		arena_allocator* currentAlloc = requestLocalMemory;
		handle_request_args* currentArg = workerArgs;
		for (int i = 0; 
			 i < N_THREADS; 
			 ++i, ++currentThreadHandle, ++currentAlloc, ++currentArg)
		{
			if (subarena(currentAlloc, &programMemory, THREAD_LOCAL_MEMORY) == -1)
			{
				retval = -1;
				goto server_clean_up;
			}

			currentArg->fileCache = &fileCache;
			currentArg->socketDescriptor = socketDescriptor;
			currentArg->requestLocalMemory = currentAlloc;

			if (pthread_create(currentThreadHandle, NULL, handleRequests, (void*) currentArg) != 0)
			{
				retval = -1;
				goto server_clean_up;
			}
		}

		if (pthread_cond_wait(&killSignal, &killMutex) != 0)
		{
			retval = -1;
			goto server_clean_up;
		}

		for (int i = 0; i < N_THREADS; ++i)
		{
			if (pthread_kill(threadHandles[i], 0) != 0)
				retval = -1;
		}
	}

server_clean_up:
	if (close(socketDescriptor) == -1)
		retval = -1;

	destroy(&programMemory);
	return retval;
}

i32 main(i32 argc, char** argv)
{
	if (pthread_mutex_init(&killMutex, NULL) != 0)
		return -1;
	if (pthread_mutex_lock(&killMutex) != 0)
		return -1;
	if (pthread_cond_init(&killSignal, NULL) != 0)
		return -1;

	if (signal(SIGINT, signalHandler) == SIG_ERR) 
	{
		fprintf(stderr, "Error while setting signal handler: %d\n", errno);
		return -1;
	}

	i16 retval = 0;
	if (serve(PORT) == -1)
		retval = -1;

	if (pthread_cond_destroy(&killSignal) != 0)
		retval = -1;
	if (pthread_mutex_unlock(&killMutex) != 0)
		return -1;
	if (pthread_mutex_destroy(&killMutex) != 0)
		return -1;

	return retval;
}
