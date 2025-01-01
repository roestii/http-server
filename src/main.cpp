// TODO(louis):
// 	- introduce proper error handling using the rfc
// 	- fix the server closing (this may be fixed)
// 	- implement some transfer encoding, for the response maybe... (but this might not actually be worth it)
// 	- parsing of the request target
// 	- obsolete line folding
// 	- connection management (close messages and timeouts) -> this would require concurrency (non blocking accept + read, and timeouts)
// 	- logging 
// 	- afl fuzzing
// 	- put requests for putting blog posts on there (with authentication)
// 	- templating for blog posts, and updates to cached blog overview page
// 	- database connection for newsletter signup (libpq)

#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <netdb.h>
#include <pthread.h>
#include <fcntl.h>

#if TLS
#include <openssl/ssl.h>
#endif

#include "http_header_map.h"
#include "arena_allocator.h"
#include "file_cache.h"
#include "types.h"
#include "string.h"
#include "http.h"
#include "authentication.h"
#include "articles.h"
#include "sqlite3.h"

constexpr u8 N_THREADS = 1;
constexpr u16 MAX_N_PENDING_CONNECTIONS = 128;
constexpr u16 PORT = 8080;

constexpr usize MEMORY_LIMIT = 10 * 1024 * 1024;
constexpr usize FILE_CACHE_LIMIT = 8 * 1024 * 1024;
constexpr usize THREAD_LOCAL_MEMORY = (MEMORY_LIMIT - FILE_CACHE_LIMIT) / N_THREADS;

#ifndef PRIVATE_KEY_PATH
#define PRIVATE_KEY_PATH "key.pem"
#endif

#ifndef CERT_PATH
#define CERT_PATH "cert.pem"
#endif

#ifndef AUTH_HASH_PATH
#define AUTH_HASH_PATH "auth.conf"
#endif

#ifndef DATABASE_PATH
#define DATABASE_PATH "users.db"
#endif

// #ifndef LOG_PATH 
// #define LOG_PATH "/var/log/http_server/http_server.log"
// #endif

#define INSERT_STMT "insert into users(email) values(?)"
#define EMAIL_PREFIX "email="
// TODO(louis):
// 		- create a character encoding table
#define AT_ENCODING "%40"
#define MIN_EMAIL_LEN 2 + sizeof(AT_ENCODING) - 1

CONST_MEMEQL(memEqlEmailPrefix, EMAIL_PREFIX);

pthread_mutex_t killMutex;
pthread_cond_t killSignal;

#if TLS
#define sockRead(a, b, c) SSL_read(a, b, c)
#define sockWrite(a, b, c) SSL_write(a, b, c)
typedef SSL* write_handle; 
#else
#define sockRead(a, b, c) read(a, b, c)
#define sockWrite(a, b, c) write(a, b, c)
typedef i32 write_handle;
#endif

// FILE* logStream = stderr;
#define log(msg, ...) fprintf(stderr, msg __VA_OPT__(,) __VA_ARGS__)

u8 putPasswdHash[SHA256_DIGEST_LENGTH];

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

i16 writeResponse(write_handle wh, http_response* response, buffered_response_writer* writer)
{
	char* statusLine = (char*) lookupStatusLine(response->statusCode);
	if (pushStr(writer, statusLine) == -1)
		return -1;

	char* reason = response->reason;
	if (reason && pushStr(writer, reason) == -1)
		return -1;

	if (pushStr(writer, (char*) CRLF) == -1)
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
		if (pushString(writer, &fieldName) == -1)
			return -1;
		if (pushChar(writer, ':') == -1)
			return -1;
		if (pushString(writer, &fieldValue) == -1)
			return -1;
		// TODO(louis): discarding the const here, might cause performance issues.
		if (pushStr(writer, (char*) CRLF) == -1)
			return -1;
	}

	if (pushStr(writer, (char*) CRLF) == -1)
		return -1;

	string messageBody = response->messageBody;
	if (messageBody.ptr && pushString(writer, &messageBody) == -1)
		return -1;
	
	if (sockWrite(wh, writer->buffer, writer->offset) == -1)
		return -1;

	return 0;
}

void handleGetRequest(http_response* result, http_request* request, 
					  file_cache* fileCache, arena_allocator* alloc)
{
	file_bucket file;
	
	string requestTarget = request->requestTarget;

	if (*requestTarget.ptr == '/')
	{
		++requestTarget.ptr;
		--requestTarget.len;
	}

	if (requestTarget.len == 0)
	{
		initEmptyResponse(result, NOT_FOUND);
		return;
	}

	// TODO(louis): Should we acquire the mutex every time? Writes to the file cache are very rare.
	if (get(&file, fileCache, &requestTarget) <= 0)
	{
		initEmptyResponse(result, NOT_FOUND);
		return;
	}

	result->statusCode = OK;
	result->reason = NULL;
	result->messageBody = 
	{ 
		file.content, 
		(isize) file.contentLen
	};

	string contentLengthValue;
	u64ToStr(&contentLengthValue, alloc, file.contentLen);
	insert(&result->headerMap, (string*) &CONTENT_LENGTH_HEADER_NAME, &contentLengthValue);
}

i16 validateEmail(string* email)
{
	char* atPtr = memFindMem(email->ptr, email->len, (char*) AT_ENCODING, sizeof(AT_ENCODING) - 1);
	if (!atPtr)
		return 0;

	u32 nameLen = atPtr - email->ptr;
	u32 domainLen = email->len - nameLen - (sizeof(AT_ENCODING) - 1);

	return nameLen != 0 && domainLen != 0;
}

// TODO(louis): introduce error handling in case the database fails.
i32 handlePostRequest(http_response* result, http_request* request, 
					   arena_allocator* alloc, sqlite3* db, sqlite3_stmt* stmt)
{
	// NOTE(louis): the caller has to ensure that the headerMap of the result was initialized.
	string transferCoding;
	string contentLength;
	i16 hasTransferCoding = getHash(&transferCoding, &request->headerMap, 
								 	TRANSFER_ENCODING_HASH, (string*) &TRANSFER_ENCODING_HEADER_NAME);
	i16 hasContentLength = getHash(&contentLength, &request->headerMap, 
								   CONTENT_LENGTH_HASH, (string*) &CONTENT_LENGTH_HEADER_NAME);

	if (hasTransferCoding && hasContentLength)
	{
		initEmptyResponse(result, BAD_REQUEST);
		return 0;
	}
	else if (hasTransferCoding)
	{
		initEmptyResponse(result, NOT_IMPLEMENTED);
		return 0;
	}
	else if (hasContentLength)
	{
		string messageBody = request->messageBody;
		u64 contentLengthInt;
		if (strToU64(&contentLengthInt, &contentLength) == -1)
		{
			initEmptyResponse(result, BAD_REQUEST);
			return 0;
		}

		if (contentLengthInt > messageBody.len)
		{
			initEmptyResponse(result, TOO_LARGE);
			return 0;
		}

		if (stringEql(&request->requestTarget, (string*) &NEWSLETTER_SIGNUP_ROUTE))
		{
			initEmptyResponse(result, OK);
			insert(&result->headerMap, (string*) &CONTENT_LENGTH_HEADER_NAME, (string*) &ZERO_LEN);

			if (messageBody.len < sizeof(EMAIL_PREFIX) - 1 + MIN_EMAIL_LEN)
			{
				initEmptyResponse(result, BAD_REQUEST);
				return 0;
			}

			if (!memEqlEmailPrefix(messageBody.ptr))
			{
				initEmptyResponse(result, BAD_REQUEST);
				return 0;
			}

			string email = 
			{
				messageBody.ptr + sizeof(EMAIL_PREFIX) - 1,
				messageBody.len - (isize) (sizeof(EMAIL_PREFIX) - 1)
			};
		
			if (!validateEmail(&email))
			{
				initEmptyResponse(result, BAD_REQUEST);
				return 0;
			}
	
			// TODO(louis): How do we handle broken statements? 
			
			i32 rc = sqlite3_bind_text(stmt, 1, email.ptr, email.len, SQLITE_STATIC);
			if (rc != SQLITE_OK)
			{
				log("Cannot bind text paramater to sqlite statement.\n");
				initEmptyResponse(result, INTERNAL_SERVER_ERROR);
				return rc;
			}

			rc = sqlite3_step(stmt);
			if (rc != SQLITE_DONE)
			{
				log("Cannot execute statement insert statement.\n");
				initEmptyResponse(result, INTERNAL_SERVER_ERROR);
				return rc;
			}

			rc = sqlite3_reset(stmt);
			if (rc != SQLITE_OK)
			{
				log("Cannot reset statement.\n");
				initEmptyResponse(result, INTERNAL_SERVER_ERROR);
				return rc;
			}

			rc = sqlite3_clear_bindings(stmt);
			if (rc != SQLITE_OK)
			{
				log("Cannot clear statment bindings.\n");
				initEmptyResponse(result, INTERNAL_SERVER_ERROR);
				return rc;
			}

			return 0;
		}
		else
		{
			initEmptyResponse(result, NOT_FOUND);
			return 0;
		}
	}
	else
	{
		initEmptyResponse(result, BAD_REQUEST);
		return 0;
	}
}

void handlePutRequest(http_response* result, http_request* request, 
					  arena_allocator* alloc, articles_resource* resource)
{
	// NOTE(louis): the caller has to ensure that the headerMap of the result was initialized.
	string transferCoding;
	string contentLength;
	string auth;

	i16 hasTransferCoding = getHash(&transferCoding, &request->headerMap, 
								 	TRANSFER_ENCODING_HASH, (string*) &TRANSFER_ENCODING_HEADER_NAME);
	i16 hasContentLength = getHash(&contentLength, &request->headerMap, 
								   CONTENT_LENGTH_HASH, (string*) &CONTENT_LENGTH_HEADER_NAME);
	i16 hasAuth = getHash(&auth, &request->headerMap, 
						  AUTH_HEADER_HASH, (string*) &AUTH_HEADER_NAME);

	if (!hasAuth)
	{
		initEmptyResponse(result, BAD_REQUEST);
		return;
	}

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

		if (stringEql(&request->requestTarget, (string*) &ADD_ARTICLE_ROUTE))
		{
			if (authenticate(&auth, putPasswdHash))
			{
				string fileName;
				i16 hasFileName = getHash(&fileName, &request->headerMap, 
						  			  	  FILENAME_HEADER_HASH, (string*) &FILENAME_HEADER_NAME);

				if (!hasFileName)
				{
					initEmptyResponse(result, BAD_REQUEST);
					return;
				}

				if (putArticle(resource, fileName.ptr, fileName.len, 
			   			   	   messageBody.ptr, contentLengthInt) == -1)
				{
					initEmptyResponse(result, INTERNAL_SERVER_ERROR);
					return;
				}

				initEmptyResponse(result, OK);
				insert(&result->headerMap, (string*) &CONTENT_LENGTH_HEADER_NAME, (string*) &ZERO_LEN);
			}
			else
			{
				initEmptyResponse(result, BAD_REQUEST);
			}
		}
		else
		{
			initEmptyResponse(result, NOT_FOUND);
			return;
		}
	}
	else
		initEmptyResponse(result, BAD_REQUEST);
}

struct handle_request_args 
{
	file_cache* fileCache;
	arena_allocator* requestLocalMemory;
	i32 socketDescriptor;
	articles_resource* resource;
	sqlite3* db;
#if TLS
	SSL_CTX* ctx;
#endif
};

void* handleRequests(void* args)
{
	handle_request_args* handleRequestArgs = (handle_request_args*) args;
	file_cache* fileCache = handleRequestArgs->fileCache;
	arena_allocator* requestLocalMemory = handleRequestArgs->requestLocalMemory;
	i32 socketDescriptor = handleRequestArgs->socketDescriptor;
	articles_resource* resource = handleRequestArgs->resource;
	sqlite3* db = handleRequestArgs->db;

#if TLS
	SSL_CTX* ctx = handleRequestArgs->ctx;
	SSL* ssl = NULL;
#endif

	char* errMsg;
	i32 rc;

	sqlite3_stmt* stmt;
	rc = sqlite3_prepare_v2(db, INSERT_STMT, sizeof(INSERT_STMT), &stmt, NULL);
	if (rc != SQLITE_OK)
		return NULL;

	http_request request;
	http_response response;
	init(&request.headerMap);
	init(&response.headerMap);

	for (;;)
	{
		// TODO(louis): spawn multiple threads that can accept and handle connections.
		i32 readBytes;
		struct sockaddr_in clientSocketAddr;
		socklen_t addrlen;
		
		i32 clientSocketDescriptor = accept(socketDescriptor, (struct sockaddr*) &clientSocketAddr, &addrlen);
		if (clientSocketDescriptor == -1)
			// TODO(louis): Implement some proper error handling (see man page).
			continue;

#if TLS
		ssl = SSL_new(ctx);

		if (!ssl)
	  	{
			fprintf(stderr, "Cannot acquire ssl object.\n");
			goto close_client_socket;
		}

		if (!SSL_set_fd(ssl, clientSocketDescriptor))
	  	{
			fprintf(stderr, "Cannot set fd for ssl object.\n");
			goto close_client_socket;
		}

		if (SSL_accept(ssl) <= 0)
	  	{
			// TODO(louis): check for the individual return values.
			fprintf(stderr, "Cannot establish ssl connection.\n");
			goto close_client_socket;
		}
#endif

		char requestBuffer[MAX_HTTP_MESSAGE_LEN];

		buffered_response_writer writer;
		init(&writer);
#if TLS
		readBytes = sockRead(ssl, requestBuffer, MAX_HTTP_HEADER_LEN);	
#else
		readBytes = sockRead(clientSocketDescriptor, requestBuffer, MAX_HTTP_HEADER_LEN);	
#endif

		if (readBytes <= 0)
			goto close_client_socket;

		u16 errorCode;
		if (parseHttpRequest(&errorCode, &request, requestBuffer, readBytes) == CORRUPTED_HEADER)
		{
			// TODO(louis): replace this with the actual error code, and maybe make this more performant
			pushStr(&writer, (char*) lookupStatusLine(BAD_REQUEST));
			pushStr(&writer, (char*) CRLF);
			pushStr(&writer, (char*) CRLF);
#if TLS
			sockWrite(ssl, (void*) writer.buffer, writer.offset);
#else
			sockWrite(clientSocketDescriptor, (void*) writer.buffer, writer.offset);
#endif
			goto close_client_socket;
		}

		string hostHeaderField;
		if (!getHash(&hostHeaderField, &request.headerMap, 
					 HOST_HEADER_HASH, (string*) &HOST_HEADER_NAME))
		{
			pushStr(&writer, (char*) lookupStatusLine(BAD_REQUEST));
			pushStr(&writer, (char*) CRLF);
			pushStr(&writer, (char*) CRLF);
#if TLS
			sockWrite(ssl, (void*) writer.buffer, writer.offset);
#else
			sockWrite(clientSocketDescriptor, (void*) writer.buffer, writer.offset);
#endif
			goto close_client_socket;
		}

		if (readBytes == MAX_HTTP_HEADER_LEN)
		{
#if TLS
			i32 n = sockRead(ssl, requestBuffer + MAX_HTTP_HEADER_LEN, 
						 MAX_HTTP_MESSAGE_LEN - MAX_HTTP_HEADER_LEN);
#else
			i32 n = sockRead(clientSocketDescriptor, requestBuffer + MAX_HTTP_HEADER_LEN, 
						 MAX_HTTP_MESSAGE_LEN - MAX_HTTP_HEADER_LEN);
#endif
			
			if (n > 0)
			{
				if (request.messageBody.ptr)
					request.messageBody.len += n;
				else
				{
	  				request.messageBody = 
					{
						requestBuffer + MAX_HTTP_HEADER_LEN,
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
#if TLS
				if (writeResponse(ssl, &response, &writer) == -1)
#else
				if (writeResponse(clientSocketDescriptor, &response, &writer) == -1)
#endif
					goto close_client_socket;

				break;
			}
			case POST:
			{
				i32 rc = handlePostRequest(&response, &request, requestLocalMemory, db, stmt);
				if (rc != SQLITE_OK)
				{
					// TODO(louis):
					assert(!"The database is broken, handle it properly...");
				}

#if TLS
				if (writeResponse(ssl, &response, &writer) == -1)
#else
				if (writeResponse(clientSocketDescriptor, &response, &writer) == -1)
#endif
					goto close_client_socket;

				break;
			}
			case PUT:
			{
				handlePutRequest(&response, &request, requestLocalMemory, resource);
#if TLS
				if (writeResponse(ssl, &response, &writer) == -1)
#else
				if (writeResponse(clientSocketDescriptor, &response, &writer) == -1)
#endif
					goto close_client_socket;

				break;
			}
		}

	close_client_socket:
#if TLS
	  	if (ssl)
	  	{
			SSL_shutdown(ssl);
			SSL_free(ssl);
		}
#endif

		reset(&writer);
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

#if TLS
	SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
	if (!ctx)
	{
		log("Cannot aquire ssl context.\n");
		return -1;
	}

	if (SSL_CTX_use_certificate_chain_file(ctx, CERT_PATH) <= 0)
	{
		log("Cannot load ssl certificate.\n");
		return -1;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY_PATH, SSL_FILETYPE_PEM) <= 0)
	{
		log("Cannot load private key.\n");
		return -1;
	}
#endif

	struct protoent* tcpProto = getprotobyname("tcp");
	if(!tcpProto)
		return -1;

	arena_allocator programMemory;
	if (init(&programMemory, MEMORY_LIMIT) == -1)
		assert(!"Cannot acquire memory.\n");

	arena_allocator fileCacheMemory;
	if (subarena(&fileCacheMemory, &programMemory, FILE_CACHE_LIMIT) == -1)
		assert(!"Cannot instantiate subarena.\n");

	i32 socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
	if (socketDescriptor == -1)
	{
		log("Cannot open socket.\n");
		return -1;
	}

	i32 optval = 1;
	struct sockaddr_in socketAddr;
	if (!inet_pton(AF_INET, "0.0.0.0", &socketAddr.sin_addr))
		assert(!"Invalid ip address.\n");

	socketAddr.sin_family = AF_INET;
	socketAddr.sin_port = htons(port);

#if DEBUG_MODE 
	if (setsockopt(socketDescriptor, SOL_SOCKET, 
			   	   SO_REUSEADDR, &optval, sizeof(optval)) == -1)
	{
		log("Cannot set socket option as reuseaddr.\n");
		retval = -1;
		goto server_clean_up;
	}
#endif

	if (bind(socketDescriptor, 
		 	 (struct sockaddr*) &socketAddr, 
		  	 sizeof(socketAddr)) == -1)
	{
		log("Cannot bind to address.\n");
		retval = -1;
		goto server_clean_up;
	}

	if (listen(socketDescriptor, MAX_N_PENDING_CONNECTIONS) == -1)
	{
		log("Cannot listen on socket bound to address.\n");
		retval = -1;
		goto server_clean_up;
	}

	{
		file_cache fileCache;
		if (init(&fileCache, &fileCacheMemory) == -1)
		{
			log("Cannot initialize file cache.\n");
			retval = -1;
			goto server_clean_up;
		}

		if (buildStaticCache(&fileCache) == -1)
		{
			log("Cannot build file cache.\n");
			retval = -1;
			goto server_clean_up;
		}

		articles_resource resource;
		init(&resource);

		pthread_t threadHandles[N_THREADS];
		arena_allocator requestLocalMemory[N_THREADS];
		handle_request_args workerArgs[N_THREADS];
		sqlite3* dbConns[N_THREADS];

		pthread_t* currentThreadHandle = threadHandles;
		arena_allocator* currentAlloc = requestLocalMemory;
		handle_request_args* currentArg = workerArgs;
		sqlite3** currentDb = dbConns;

		for (int i = 0; 
			 i < N_THREADS; 
			 ++i, ++currentThreadHandle, 
			 ++currentAlloc, ++currentArg, ++currentDb)
		{
			if (sqlite3_open(DATABASE_PATH, currentDb) != SQLITE_OK)
			{
				log("Cannot open database file.\n");
				retval = -1;
				goto server_clean_up;
			}

			if (subarena(currentAlloc, &programMemory, THREAD_LOCAL_MEMORY) == -1)
				assert(!"Unable to instantiate subarena");

			currentArg->fileCache = &fileCache;
			currentArg->socketDescriptor = socketDescriptor;
			currentArg->requestLocalMemory = currentAlloc;
			currentArg->resource = &resource;
			currentArg->db = *currentDb;
#if TLS
			currentArg->ctx = ctx;
#endif

			if (pthread_create(currentThreadHandle, NULL, handleRequests, (void*) currentArg) != 0)
			{
				log("Unable to create thread.\n");
				retval = -1;
				goto server_clean_up;
			}
		}

		if (pthread_cond_wait(&killSignal, &killMutex) != 0)
		{
			log("Unable to wait on cond.\n");
			retval = -1;
			goto server_clean_up;
		}

		for (int i = 0; i < N_THREADS; ++i)
		{
			if (pthread_kill(threadHandles[i], 0) != 0)
				retval = -1;

			if (sqlite3_close(dbConns[i]) != SQLITE_OK)
				retval = -1;
		}

		destroy(&fileCache);
	}

server_clean_up:
	if (close(socketDescriptor) == -1)
		retval = -1;

#if TLS
	SSL_CTX_free(ctx);
#endif
	destroy(&programMemory);
	return retval;
}

i16 loadEnv()
{
	i16 retval = 0;
	i32 fd = open(AUTH_HASH_PATH, O_RDONLY);
	if (fd == -1)
	{
		log("Cannot open auth config.\n");
		return -1;
	}

	char passwdHashStr[2 * SHA256_DIGEST_LENGTH];
	i32 n = read(fd, (void*) passwdHashStr, sizeof(passwdHashStr));
	if (n != sizeof(passwdHashStr))
	{
		log("Unable to read password hash from auth config.\n");
		retval = -1;
	}

	if (hexdecodeSHA256(putPasswdHash, passwdHashStr) == -1)
	{
		log("Invalid auth config format.");
		retval = -1;
	}

	if (close(fd) == -1)
		retval = -1;

	return retval;
}

i32 main(i32 argc, char** argv)
{
	if (loadEnv() == -1)
	{
		log("Cannot read authentication config.\n");
		return -1;
	}

	// log = fopen(LOG_PATH, "a");
	// if (!log)
	// 	return -1;

	if (pthread_mutex_init(&killMutex, NULL) != 0)
		return -1;
	if (pthread_mutex_lock(&killMutex) != 0)
		return -1;
	if (pthread_cond_init(&killSignal, NULL) != 0)
		return -1;

	if (signal(SIGINT, signalHandler) == SIG_ERR) 
	{
		log("Error while setting signal handler: %d\n", errno);
		return -1;
	}

	i16 retval = 0;
	if (serve(PORT) == -1)
		retval = -1;

	// fclose(log);

	if (pthread_cond_destroy(&killSignal) != 0)
		retval = -1;
	if (pthread_mutex_unlock(&killMutex) != 0)
		return -1;
	if (pthread_mutex_destroy(&killMutex) != 0)
		return -1;

	return retval;
}
