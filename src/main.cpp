#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "types.h"
#include "parser.h"

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

i32 serve(u16 port)
{
	socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
	if (socketDescriptor == -1)
	{
		return -1;

	}

	struct sockaddr_in socketAddr;
	if (!inet_pton(AF_INET, "0.0.0.0", &socketAddr.sin_addr))
	{
		goto close_server_socket;
	}

	socketAddr.sin_family = AF_INET;
	socketAddr.sin_port = htons(port);

	if (bind(socketDescriptor, 
		 	 (struct sockaddr*) &socketAddr, 
		  	 sizeof(socketAddr)) == -1)
	{
		goto close_server_socket;
	}

	if (listen(socketDescriptor, MAX_N_PENDING_CONNECTIONS) == -1)
	{
		goto close_server_socket;
	}

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
			{
				goto close_client_socket;
			}

			http_header httpHeader;
			if (parseHeader(&httpHeader, buffer, readBytes) == -1)
			{
				goto close_client_socket;
			}
			printf("\n");
		}

	close_client_socket:
		if (clientSocketDescriptor >= 0)
		{
			if (close(clientSocketDescriptor) == -1)
			{
				goto close_server_socket;
			}
		}
	}

close_server_socket:
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
