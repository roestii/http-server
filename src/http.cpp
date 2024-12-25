#include <stdio.h>
#include <assert.h>

#include "http.h"
#include "mem.h"

constexpr u8 MAX_DIGITS_U8 = 3;

void initEmptyResponse(http_response* result, http_status_code statusCode)
{
	result->statusCode = statusCode;
	result->reason = NULL;
	result->messageBody = {0};
}

const char* lookupStatusLine(http_status_code statusCode)
{
	// NOTE(louis): The caller has to ensure that the input is in fact a BASIC_RESPONSE. 
	// Otherwise this is unsafe to call.

	switch (statusCode)
	{
		case OK: return OK_RESPONSE;
		case BAD_REQUEST: return BAD_REQUEST_RESPONSE;
		case NOT_IMPLEMENTED: return NOT_IMPLEMENTED_RESPONSE;
		case NOT_FOUND: return NOT_FOUND_RESPONSE;
		default: __builtin_unreachable();
	}
}

// TODO(louis): make this more safe...
u8 strnToU8(char** firstInvalidPtr, char* str, u8 strLen)
{
	u8 digits[MAX_DIGITS_U8] = {0};
	u8 nDigits = 0;
	u8 minSize = MAX_DIGITS_U8;
	if (strLen < MAX_DIGITS_U8)
		minSize = strLen;

	for (;nDigits < minSize; ++nDigits, ++str)
	{ 
		u8 digit = *str - 0x30;
		if (digit < 0 || digit > 9)
			break;

		digits[nDigits] = digit;
	}
	
	*firstInvalidPtr = str;
	u8 result = 0;
	u8 power = 1;

	for (int i = nDigits - 1; i >= 0; --i)
	{
		result += digits[i] * power;
		power *= 10;
	}

	return result;
}

i16 parseFieldLines(http_header_map* headerMap, char* headerFieldLineStr, char* headerFieldLineEndPtr)
{
	string fieldName;
	string fieldValue;

	for (;;)
	{
		if (headerFieldLineStr == headerFieldLineEndPtr)
			return 0;

		char* nextCrlfPtr = memFindCrlf(headerFieldLineStr, headerFieldLineEndPtr - headerFieldLineStr);
		if (!nextCrlfPtr)
			return -1;

		char* colonPtr = memFindChr(headerFieldLineStr, nextCrlfPtr - headerFieldLineStr, ':');
		if (!colonPtr)
			return -1;

		if (*(colonPtr - 1) == ' ')
			return -1;

		char* headerValuePtr = colonPtr + 1;
		if (headerValuePtr == nextCrlfPtr)
			return -1;

		if (*headerValuePtr == ' ')
		{
			++headerValuePtr;
			if (headerValuePtr == nextCrlfPtr)
				return -1;
		}

		isize fieldValueLen = nextCrlfPtr - headerValuePtr;
		if (*(nextCrlfPtr - 1) == ' ')
			--fieldValueLen;

		fieldName = { headerFieldLineStr, colonPtr - headerFieldLineStr };
		fieldValue = { headerValuePtr, fieldValueLen };
		if (insert(headerMap, &fieldName, &fieldValue) == -1)
			return -1;

		headerFieldLineStr = nextCrlfPtr + CRLF_LEN;
	}		

	return 0;
}

i16 parseHttpRequest(u16* errorCode, http_request* result, char* buffer, u32 readBytes)
{
	// NOTE(louis): Returns the pointer to the start of the message body if there is any.
	// TODO(louis): Introduce proper error handling
	
	char* messageEndPtr = buffer + readBytes;
	char* crlfPointer = memFindCrlf(buffer, readBytes);
	if (!crlfPointer)
		return CORRUPTED_HEADER;

	usize requestLineSize = crlfPointer - buffer;
	char* requestTargetPtr = memFindChr(buffer, requestLineSize, SP);

	if (!requestTargetPtr)
		return CORRUPTED_HEADER;

	usize methodLen = requestTargetPtr - buffer;
	http_method httpMethod;

	switch (methodLen)
	{
		case GET_METHOD_NAME_LEN:
		{
			if (memEqlGet(buffer)) 
				result->method = GET;
			else 
				// TODO(louis): set the error code.
				return CORRUPTED_HEADER;

			break;
		}
		case POST_METHOD_NAME_LEN:
		{
			if (memEqlPost(buffer)) 
				result->method = POST;
			else 
				// TODO(louis): set the error code. and move this into a constant
				return CORRUPTED_HEADER;

			break;
		}
		default:
			// TODO(louis): set the error code.
			return CORRUPTED_HEADER;
	}

	++requestTargetPtr;
	isize remainingSize = crlfPointer - requestTargetPtr;
	if (remainingSize <= 0)
		return CORRUPTED_HEADER;

	char* httpVersionPtr = memFindChr(requestTargetPtr, remainingSize, SP);
	if (!httpVersionPtr)
		return CORRUPTED_HEADER;

	isize requestTargetLen = httpVersionPtr - requestTargetPtr;
	if (requestTargetLen <= 0)
		return CORRUPTED_HEADER;

	result->requestTarget = { requestTargetPtr, requestTargetLen };

	++httpVersionPtr;
	isize httpVersionLen = crlfPointer - httpVersionPtr;
	if (httpVersionLen <= 0 || httpVersionLen < HTTP_VERSION_PREFIX_LEN + 3)
		return CORRUPTED_HEADER;

	if (!memEqlHttpVersionPrefix(httpVersionPtr))
		return CORRUPTED_HEADER;

	httpVersionPtr += HTTP_VERSION_PREFIX_LEN;
	char* dotPtr; 
	u8 majorVersion = strnToU8(&dotPtr, httpVersionPtr, crlfPointer - httpVersionPtr);
	if (httpVersionPtr == dotPtr || *dotPtr != '.')
		return CORRUPTED_HEADER;

	++dotPtr;
	if (dotPtr >= crlfPointer)
		return CORRUPTED_HEADER;

	u8 minorVersion = strnToU8(&httpVersionPtr, dotPtr, crlfPointer - dotPtr);
	if (httpVersionPtr != crlfPointer)
		return CORRUPTED_HEADER;

	result->version.major = majorVersion;
	result->version.minor = minorVersion;

	char* headerFieldLineStartPtr = crlfPointer + CRLF_LEN;
	if (headerFieldLineStartPtr >= messageEndPtr)
		return CORRUPTED_HEADER;

	char* headerFieldLineEndPtr = memFind2Crlf(headerFieldLineStartPtr, messageEndPtr - headerFieldLineStartPtr);
	if (!headerFieldLineEndPtr)
		return CORRUPTED_HEADER;

	if (parseFieldLines(&result->headerMap, headerFieldLineStartPtr, 
					 	headerFieldLineEndPtr + CRLF_LEN) == -1)
		return CORRUPTED_HEADER;

	char* messageBodyStartPtr = headerFieldLineEndPtr + 2 * CRLF_LEN;
	isize messageBodyLen = messageEndPtr - messageBodyStartPtr;
	if (messageBodyLen <= 0)
		result->messageBody = {0};
	else
		result->messageBody = { messageBodyStartPtr, messageBodyLen };

	return 0;
}
