#include <stdio.h>
#include <assert.h>

#include "http.h"
#include "mem.h"

constexpr u8 MAX_DIGITS_U8 = 3;
constexpr u8 STATUS_CODE_DIGITS = 3;

const u8* lookupResponse(http_status_code statusCode)
{
	// NOTE(louis): The caller has to ensure that the input is in fact a BASIC_RESPONSE. 
	// Otherwise this is unsafe to call.

	switch (statusCode)
	{
		case OK: return OK_RESPONSE;
		case BAD_REQUEST: return BAD_REQUEST_RESPONSE;
		case NOT_IMPLEMENTED: return NOT_IMPLEMENTED_RESPONSE;
		default: __builtin_unreachable();
	}
}

u8 strnToU8(u8** firstInvalidPtr, u8* str, u8 strLen)
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

i16 parseFieldLines(http_header_map* headerMap, u8* headerFieldLineStr, u8* headerFieldLineEndPtr)
{
	string fieldName;
	string fieldValue;

	for (;;)
	{
		if (headerFieldLineStr == headerFieldLineEndPtr)
			return 0;

		u8* nextCrlfPtr = memFindCrlf(headerFieldLineStr, headerFieldLineEndPtr - headerFieldLineStr);
		if (!nextCrlfPtr)
			return -1;

		u8* colonPtr = memFindChr(headerFieldLineStr, nextCrlfPtr - headerFieldLineStr, ':');
		if (!colonPtr)
			return -1;

		if (*(colonPtr - 1) == ' ')
			return -1;

		u8* headerValuePtr = colonPtr + 1;
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

		headerFieldLineStr = nextCrlfPtr + sizeof(CRLF);
	}		

	return 0;
}

u8* parseHeader(u16* errorCode, http_header* result, u8* buffer, u32 readBytes)
{
	// NOTE(louis): Returns the pointer to the start of the message body if there is any.
	//
	// TODO(louis): Introduce proper error handling
	u8* limit = buffer + readBytes;
	u8* crlfPointer = memFindCrlf(buffer, readBytes);
	if (!crlfPointer)
		return (u8*) -1;

	usize requestLineSize = crlfPointer - buffer;
	u8* requestTargetPtr = memFindChr(buffer, requestLineSize, SP);

	if (!requestTargetPtr)
		return (u8*) -1;

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
				return (u8*) -1;

			break;
		}
		case POST_METHOD_NAME_LEN:
		{
			if (memEqlPost(buffer)) 
				result->method = POST;
			else 
				// TODO(louis): set the error code.
				return (u8*) -1;

			break;
		}
		default:
			// TODO(louis): set the error code.
			return (u8*) -1;
	}

	++requestTargetPtr;
	isize remainingSize = crlfPointer - requestTargetPtr;
	if (remainingSize <= 0)
		return (u8*) -1;

	u8* httpVersionPtr = memFindChr(requestTargetPtr, remainingSize, SP);
	if (!httpVersionPtr)
		return (u8*) -1;

	isize requestTargetLen = httpVersionPtr - requestTargetPtr;
	if (requestTargetLen <= 0)
		return (u8*) -1;

	result->requestTarget = { requestTargetPtr, requestTargetLen };

	++httpVersionPtr;
	isize httpVersionLen = crlfPointer - httpVersionPtr;
	if (httpVersionLen <= 0 || httpVersionLen < sizeof(HTTP_VERSION_PREFIX) + 3)
		return (u8*) -1;

	if (!memEqlHttpVersionPrefix(httpVersionPtr))
		return (u8*) -1;

	httpVersionPtr += sizeof(HTTP_VERSION_PREFIX);
	u8* dotPtr; 
	u8 majorVersion = strnToU8(&dotPtr, httpVersionPtr, crlfPointer - httpVersionPtr);
	if (httpVersionPtr == dotPtr || *dotPtr != '.')
		return (u8*) -1;

	++dotPtr;
	if (dotPtr >= crlfPointer)
		return (u8*) -1;

	u8 minorVersion = strnToU8(&httpVersionPtr, dotPtr, crlfPointer - dotPtr);
	if (httpVersionPtr != crlfPointer)
		return (u8*) -1;

	result->version.major = majorVersion;
	result->version.minor = minorVersion;

	u8* headerFieldLineStartPtr = crlfPointer + sizeof(CRLF);
	if (headerFieldLineStartPtr >= limit)
		return (u8*) -1;

	u8* headerFieldLineEndPtr = memFind2Crlf(headerFieldLineStartPtr, limit - headerFieldLineStartPtr);
	if (!headerFieldLineEndPtr)
		return (u8*) -1;

	if (parseFieldLines(&result->headerMap, headerFieldLineStartPtr, 
					 	headerFieldLineEndPtr + sizeof(CRLF)) == -1)
		return (u8*) -1;

	u8* messageBodyStartPtr = headerFieldLineEndPtr + 2 * sizeof(CRLF);
	if (messageBodyStartPtr >= limit)
		return NULL;

	return messageBodyStartPtr;
}
