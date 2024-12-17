#include <stdio.h>
#include <assert.h>

#include "http.h"
#include "mem.h"

constexpr u8 MAX_DIGITS_U8 = 3;

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

i16 parseFieldLines(http_header_map* headerMap, u8* headerLineStr, u8* limit)
{
	string fieldName;
	string fieldValue;

	for (;;)
	{
		if (limit - headerLineStr >= 2 && memEqlCrlf(headerLineStr))
			return 0;

		u8* nextCrlfPtr = memFindCrlf(headerLineStr, limit - headerLineStr);
		if (!nextCrlfPtr)
			return -1;

		u8* colonPtr = memFindChr(headerLineStr, nextCrlfPtr - headerLineStr, ':');
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

		usize fieldValueLen = nextCrlfPtr - headerValuePtr;
		if (*(nextCrlfPtr - 1) == ' ')
			--fieldValueLen;

		fieldName = { headerLineStr, colonPtr - headerLineStr };
		fieldValue = { headerValuePtr, fieldValueLen };
		if (insert(headerMap, &fieldName, &fieldValue) == -1)
			return -1;

		headerLineStr = nextCrlfPtr + sizeof(CRLF);
	}		

	return 0;
}

i16 parseHeader(http_header* result, u8* buffer, u32 readBytes)
{
	// TODO(louis): Introduce proper error handling
	u8* limit = buffer + readBytes;
	u8* crlfPointer = memFindCrlf(buffer, readBytes);
	if (!crlfPointer)
	{
		return -1;
	}

	usize requestLineSize = crlfPointer - buffer;
	u8* requestTargetPtr = memFindChr(buffer, requestLineSize, SP);

	if (!requestTargetPtr)
	{
		return -1;
	}

	usize methodLen = requestTargetPtr - buffer;
	http_method httpMethod;

	switch (methodLen)
	{
		case GET_METHOD_NAME_LEN:
		{
			if (memEqlGet(buffer)) 
			{
				result->method = GET;
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
			if (memEqlPost(buffer)) 
			{
				result->method = POST;
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

	++requestTargetPtr;
	isize remainingSize = crlfPointer - requestTargetPtr;
	if (remainingSize <= 0)
	{
		return -1;
	}

	u8* httpVersionPtr = memFindChr(requestTargetPtr, remainingSize, SP);
	if (!httpVersionPtr)
	{
		return -1;
	}

	i32 requestTargetLen = httpVersionPtr - requestTargetPtr;
	if (requestTargetLen <= 0)
	{
		return -1;
	}

	result->requestTarget = { requestTargetPtr, requestTargetLen };

	++httpVersionPtr;
	isize httpVersionLen = crlfPointer - httpVersionPtr;
	if (httpVersionLen <= 0 || httpVersionLen < sizeof(HTTP_VERSION_PREFIX) + 3)
	{
		return -1;
	}

	if (!memEqlHttpVersionPrefix(httpVersionPtr))
	{
		return -1;
	}

	httpVersionPtr += sizeof(HTTP_VERSION_PREFIX);
	u8* dotPtr; 
	u8 majorVersion = strnToU8(&dotPtr, httpVersionPtr, crlfPointer - httpVersionPtr);
	if (httpVersionPtr == dotPtr || *dotPtr != '.')
	{
		return -1;
	}

	++dotPtr;
	if (dotPtr >= crlfPointer)
	{
		return -1;
	}

	u8 minorVersion = strnToU8(&httpVersionPtr, dotPtr, crlfPointer - dotPtr);
	if (httpVersionPtr != crlfPointer)
	{
		return -1;
	}

	result->version.major = majorVersion;
	result->version.minor = minorVersion;

	u8* headerLineStartPtr = crlfPointer + sizeof(CRLF);
	if (headerLineStartPtr <= limit)
	{
		if (parseFieldLines(&result->headerMap, 
					  		headerLineStartPtr, limit) == -1)
		{
			return -1;
		}
	}


	return 0;
}
