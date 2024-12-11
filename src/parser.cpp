#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "parser.h"

const u8 CRLF[2] = { '\r', '\n' };
const u8 SP = ' ';

constexpr u8 GET_METHOD_NAME[3] = { 'G', 'E', 'T' };
constexpr u8 POST_METHOD_NAME[4] = { 'P', 'O', 'S', 'T' };

constexpr u32 GET_METHOD_NAME_LEN = sizeof(GET_METHOD_NAME);
constexpr u32 POST_METHOD_NAME_LEN = sizeof(POST_METHOD_NAME);

i32 parseHeader(u8* buffer, u32 readBytes)
{
	// TODO(louis): Introduce proper error handling
	
	u8* crlfPointer = (u8*) memmem(buffer, readBytes, CRLF, sizeof(CRLF));
	if (!crlfPointer)
	{
		return -1;
	}

	u32 requestLineSize = crlfPointer - buffer;
	u8* spacePointer = (u8*) memchr(buffer, SP, requestLineSize);

	if (!spacePointer)
	{
		return -1;
	}

	u32 methodLen = spacePointer - buffer;
	http_method httpMethod;

	switch (methodLen)
	{
		case GET_METHOD_NAME_LEN:
		{
			if (memcmp(buffer, GET_METHOD_NAME, GET_METHOD_NAME_LEN) == 0) 
			{
				httpMethod = GET;
			}
			else 
			{
				// TODO(louis): set the error code.
				return -1;
			}

			break;
		}
		case POST_METHOD_NAME_LEN:
		{
			if (memcmp(buffer, POST_METHOD_NAME, POST_METHOD_NAME_LEN) == 0) 
			{
				httpMethod = POST;
			}
			else 
			{
				// TODO(louis): set the error code.
				return -1;
			}

			break;
		}
		default:
		{
			// TODO(louis): set the error code.
			return -1;
		}
	}

	++spacePointer;

	i32 remainingSize = crlfPointer - spacePointer;
	assert(remainingSize > 0);

	u8* spacePointerTwo = (u8*) memchr(spacePointer, SP, remainingSize);
	if (!spacePointerTwo)
	{
		return -1;
	}

	i32 requestTargetLen = spacePointerTwo - spacePointer;
	assert(requestTargetLen > 0);

	++spacePointerTwo;
	i32 httpVersionLen = crlfPointer - spacePointerTwo;

	fprintf(stdout, "http method: %d\nrequest-target %.*s\nhttp-version: %.*s\n", 
			httpMethod, requestTargetLen, spacePointer, 
		 	httpVersionLen, spacePointerTwo);
	return 0;
}
