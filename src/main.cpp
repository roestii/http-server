// TODO(louis):
//  - somehow we messed up the freeing of the connections, nice
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
// 	- pool allocator for file cache
// 	- implement conncection: close header for bad request things, and also handle connection close messages
// 	- insert actual @ rather that %40 into database 
// 	- does the epoll store the fire of the timer when it first fires then resets because of another read because by then 
// 	  the timer should not have fired in the first place (or at least the first fire should be removed)
// 	- add hot reload...
// 	- fix reloading eight times
// 	- non blocking sockets, and we have to keep state for persistent connections 

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <netdb.h>
#include <pthread.h>
#include <fcntl.h>
#include <time.h>

#if TLS
#include <openssl/ssl.h>
#endif

#include "http_header_map.h"
#include "arena_allocator.h"
#include "pool_allocator.h"
#include "file_cache.h"
#include "types.h"
#include "string.h"
#include "http.h"
#include "authentication.h"
#include "articles.h"
#include "sqlite3.h"

#define N_THREADS 1
#define MAX_N_PENDING_CONNECTIONS 128
#define PORT 8080
#define MAX_CONNECTIONS 128

#define MAX_EVENTS 16

#define MEMORY_LIMIT 1 * 1024 * 1024 * 1024
#define FILE_CACHE_SIZE 8 * 1024 * 1024
#define THREAD_LOCAL_MEMORY (MEMORY_LIMIT - FILE_CACHE_SIZE) / N_THREADS

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
#define EXPIRATION_TIME 2

CONST_MEMEQL(memEqlEmailPrefix, EMAIL_PREFIX);
CONST_FINDMEM(memFind2Crlf, "\r\n\r\n");

pthread_mutex_t killMutex;
pthread_cond_t killSignal;

#if TLS
#define sockRead(a, b, c) SSL_read(a, b, c)
#define sockWrite(a, b, c) SSL_write(a, b, c)
typedef SSL* sock_handle; 
#else
#define sockRead(a, b, c) read(a, b, c)
#define sockWrite(a, b, c) write(a, b, c)
typedef i32 sock_handle;
#endif

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

i16 writeResponse(sock_handle wh, http_response* response, buffered_response_writer* writer)
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

void handleGetRequest(http_response* result, http_header* request, 
					  char* messageBody, usize contentLength,
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
i32 handlePostRequest(http_response* result, http_header* request, 
					  char* messageBody, usize contentLength,
					  arena_allocator* alloc, sqlite3* db, sqlite3_stmt* stmt)
{
	// NOTE(louis): the caller has to ensure that the headerMap of the result was initialized.

	if (contentLength > 0)
	{
		if (stringEql(&request->requestTarget, (string*) &NEWSLETTER_SIGNUP_ROUTE))
		{
			if (contentLength < sizeof(EMAIL_PREFIX) - 1 + MIN_EMAIL_LEN)
			{
				initEmptyResponse(result, BAD_REQUEST);
				return 0;
			}

			if (!memEqlEmailPrefix(messageBody))
			{
				initEmptyResponse(result, BAD_REQUEST);
				return 0;
			}

			string email = 
			{
				messageBody + sizeof(EMAIL_PREFIX) - 1,
				(isize) contentLength - (isize) (sizeof(EMAIL_PREFIX) - 1)
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

			insert(&result->headerMap, (string*) &CONTENT_LENGTH_HEADER_NAME, (string*) &ZERO_LEN);
			initEmptyResponse(result, OK);
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

void handlePutRequest(http_response* result, http_header* request, 
					  char* messageBody, usize contentLength,
					  arena_allocator* alloc, articles_resource* resource)
{
	// NOTE(louis): the caller has to ensure that the headerMap of the result was initialized.
	string auth;
	i16 hasAuth = getHash(&auth, &request->headerMap, 
						  AUTH_HEADER_HASH, (string*) &AUTH_HEADER_NAME);

	if (!hasAuth)
	{
		initEmptyResponse(result, BAD_REQUEST);
		return;
	}

	if (contentLength > 0)
	{
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
			   			   	   messageBody, contentLength) == -1)
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
		}
	}
	else
	{	
		initEmptyResponse(result, BAD_REQUEST);
	}
}

struct http_parser
{
	http_header header;
	bool hasHeaders;
	char buffer[MAX_HTTP_MESSAGE_LEN];
	usize offset;

	char* messageBody;
	usize contentLength;
};

struct client_connection
{
	i32 fd;
#if TLS
	SSL* ssl;
#endif
	buffered_response_writer writer;
	http_response response;
	http_parser parser;
};

void init(http_parser* parser)
{
	parser->offset = 0;
	parser->contentLength = 0;
	parser->hasHeaders = false;
	parser->messageBody = NULL;
	init(&parser->header.headerMap);
}

void closeConnection(pool_allocator* alloc, client_connection* conn)
{
#if TLS
	SSL_shutdown(conn->ssl);
	SSL_free(conn->ssl);
	close(conn->fd);
#else
	close(conn->fd);
#endif

	free(alloc, conn);
}

struct handle_request_args 
{
	file_cache* fileCache;
	arena_allocator* threadLocalMemory;
	i32 socketDescriptor;
	articles_resource* resource;
	sqlite3* db;
#if TLS
	SSL_CTX* ctx;
#endif
};

i32 handleHttpRequest(client_connection* conn, file_cache* fileCache,
				  	  arena_allocator* requestLocalMemory, sqlite3* db, 
				      sqlite3_stmt* stmt)
{
	i32 retval = 0;
	buffered_response_writer* writer = &conn->writer;
	http_header* header = &conn->parser.header;
	http_response* response = &conn->response;
	char* messageBody = conn->parser.messageBody;
	usize contentLength = conn->parser.contentLength;

#if TLS
	sock_handle sockHandle = (SSL*) conn->ssl;
#else
	sock_handle sockHandle = conn->fd;
#endif

	switch (conn->parser.header.method)
	{
		case GET:
		{
			handleGetRequest(response, header, messageBody, contentLength, 
					  	     fileCache, requestLocalMemory);
			if (writeResponse(sockHandle, response, writer) == -1)
			{
				retval = -1;
				goto request_cleanup;
			}
			break;
		}
		case POST:
		{
			i32 rc = handlePostRequest(response, header, messageBody, contentLength, 
							  		   requestLocalMemory, db, stmt);
			if (rc != SQLITE_OK)
				// TODO(louis):
				assert(!"The database is broken, handle it properly...");

			if (writeResponse(sockHandle, response, writer) == -1)
			{
				retval = -1;
				goto request_cleanup;
			}
			break;
		}
		case PUT:
		{
			/* handlePutRequest(response, header, messageBody, contentLength, 
					 		 requestLocalMemory, resource);
			if (writeResponse(sockHandle, response, writer) == -1)
			{
				retval = -1;
				goto request_clean_up;
			}
			break; */
		}
	}

request_cleanup:
	reset(writer);
	clear(&response->headerMap);
	reset(requestLocalMemory);
	return retval;
}

i32 handleConnection(client_connection* conn, file_cache* fileCache, 
				  	 arena_allocator* requestLocalMemory, sqlite3* db, 
				   	 sqlite3_stmt* stmt)
{
	isize readBytes;
	i16 retval;
#if TLS
	sock_handle sockHandle = (SSL*) conn->ssl;
#else
	sock_handle sockHandle = conn->fd;
#endif

	http_parser* parser = &conn->parser;
	for (;;)
	{
		if (parser->offset >= MAX_HTTP_MESSAGE_LEN)
			return -1;

		readBytes = sockRead(sockHandle, parser->buffer + parser->offset, 
					   		 MAX_HTTP_MESSAGE_LEN - parser->offset);
		if (readBytes > 0)
		{
			parser->offset += readBytes;
			for (;;)
	  		{
				if (!parser->hasHeaders)
				{
					char* ptr = memFind2Crlf(parser->buffer, parser->offset);
					if (!ptr)
						break;

					if (parseHttpHeader(&parser->header, parser->buffer, 
										ptr + CRLF_LEN - parser->buffer) == CORRUPTED_HEADER)
						return -1;

					parser->hasHeaders = true;
					parser->messageBody = ptr + 2 * CRLF_LEN;
				}

				if (parser->hasHeaders)
				{
					string contentLengthString;
					u64 contentLength;
					i16 hasContentLength = getHash(&contentLengthString, &parser->header.headerMap, 
													CONTENT_LENGTH_HASH, (string*) &CONTENT_LENGTH_HEADER_NAME);
					if (hasContentLength)
	  				{	
						if (strToU64(&contentLength, &contentLengthString) == -1)
							return -1;

						usize remaining = parser->buffer + parser->offset - parser->messageBody;
						if (remaining < contentLength)
							break;

						parser->contentLength = contentLength;
					}

					if (handleHttpRequest(conn, fileCache, requestLocalMemory, 
					   				  	  db, stmt) == -1)
						return -1;

					memCpy(parser->buffer, parser->messageBody + parser->contentLength, 
						   parser->buffer + parser->offset - (parser->messageBody + parser->contentLength));

					parser->hasHeaders = false;
					parser->offset = 0;
					parser->contentLength = 0;
					parser->messageBody = NULL;
					clear(&parser->header.headerMap);
				}
			}
		}
		else if (readBytes == -1 && errno == EWOULDBLOCK)
			return 0;
		else
	  		return -1;
	}
}

SSL* establishSSLConnection(SSL_CTX* ctx, i32 cfd)
{
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		log("Cannot acquire ssl object.\n");
		return NULL;
	}

	if (!SSL_set_fd(ssl, cfd))
	{
		log("Cannot set fd for ssl object.\n");
		SSL_free(ssl);
		return NULL;
	}

	i32 retval, err;
	for (;;)
	{
		retval = SSL_accept(ssl);
		if (retval == -1)
	  	{	
			err = SSL_get_error(ssl, retval);
			if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
				goto ssl_fail;
		}
		else if (retval == 0)
			goto ssl_fail;
		else 
			return ssl;
	}

ssl_fail:
	log("Cannot establish ssl connection.\n");
	SSL_free(ssl);
	SSL_shutdown(ssl);
	return NULL;
}

void* handleRequests(void* args)
{
	handle_request_args* handleRequestArgs = (handle_request_args*) args;
	file_cache* fileCache = handleRequestArgs->fileCache;
	arena_allocator* threadLocalMemory = handleRequestArgs->threadLocalMemory;
	i32 serverSocket = handleRequestArgs->socketDescriptor;
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

	void* addr = allocate(threadLocalMemory, MAX_CONNECTIONS * sizeof(client_connection));
	pool_allocator connectionPool;
	init(&connectionPool, addr, 
	  	 MAX_CONNECTIONS * sizeof(client_connection), 
	  	 sizeof(client_connection));

	arena_allocator requestLocalMemory;
	consume(&requestLocalMemory, threadLocalMemory);

	i32 epollfd = epoll_create1(0);
	assert(epollfd != -1 && "Cannot create epoll");
	struct epoll_event ev, events[MAX_EVENTS];
	ev.events = EPOLLIN;
	ev.data.fd = serverSocket;
	assert(epoll_ctl(epollfd, EPOLL_CTL_ADD, serverSocket, &ev) == 0 && "Cannot add server socket to epoll");

	sock_handle sockHandle;
	i32 nfds, cfd, tfd, fd, readBytes;

	for (;;)
	{
		i32 nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		for (int i = 0; i < nfds; ++i)
		{
			fd = events[i].data.fd;
			if (fd == serverSocket)
			{
				socklen_t addrlen;
				struct sockaddr_in clientSocketAddr;
				cfd = accept4(fd, (struct sockaddr*) &clientSocketAddr, &addrlen, SOCK_NONBLOCK);
				assert(cfd != -1 && "Received invalid client socket descriptor.");
				client_connection* conn = (client_connection*) allocate(&connectionPool);
				if ((void*) conn == (void*) -1)
				{
					log("Cannot accept new connections, max connections exceeded.\n");
					close(cfd);
					continue;
				}

				conn->fd = cfd;
				init(&conn->parser);
				init(&conn->writer);
				init(&conn->response.headerMap);
#if TLS
				SSL* ssl = establishSSLConnection(ctx, cfd);
				if (!ssl)
				{
					closeConnection(&connectionPool, conn);
					continue;
				}

				conn->ssl = ssl;
#endif
				ev.data.ptr = conn;
				ev.events = EPOLLIN;
				assert(epoll_ctl(epollfd, EPOLL_CTL_ADD, cfd, &ev) != -1 && "Cannot add client socket to epoll.");
			}
			else
			{
				client_connection* conn = (client_connection*) events[i].data.ptr;
				if (handleConnection(conn, fileCache, &requestLocalMemory, db, stmt) == -1)
					closeConnection(&connectionPool, conn);
			}
		}
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

	pool_allocator fileCacheMemory;
	void* startAddr = allocate(&programMemory, FILE_CACHE_SIZE);
	assert(startAddr != (void*) -1 && "File cache doesn't fit into the memory.");
	init(&fileCacheMemory, startAddr, FILE_CACHE_SIZE, MAX_FILE_SIZE);
	i32 socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
	if (socketDescriptor == -1)
	{
		log("Cannot open socket.\n");
		return -1;
	}

	i32 optval = 1;
	struct sockaddr_in socketAddr;
	assert(inet_pton(AF_INET, "0.0.0.0", &socketAddr.sin_addr) && "Invalid ip address.");
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
		arena_allocator threadLocalMemory[N_THREADS];
		handle_request_args workerArgs[N_THREADS];
		sqlite3* dbConns[N_THREADS];

		pthread_t* currentThreadHandle = threadHandles;
		arena_allocator* currentAlloc = threadLocalMemory;
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
			currentArg->threadLocalMemory = currentAlloc;
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

	if (pthread_cond_destroy(&killSignal) != 0)
		retval = -1;
	if (pthread_mutex_unlock(&killMutex) != 0)
		return -1;
	if (pthread_mutex_destroy(&killMutex) != 0)
		return -1;

	return retval;
}
