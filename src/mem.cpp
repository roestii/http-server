#include "mem.h"

// TODO(louis): maybe speed this up with vector instruction sets
bool memEqlGet(u8* haystack)
{
	// NOTE(louis): the caller has to ensure that the size of the haystack is at least 
	// as long as GET
	return *haystack == GET_METHOD_NAME[0] 
		   && *(haystack + 1) == GET_METHOD_NAME[1]
		   && *(haystack + 2) == GET_METHOD_NAME[2];
}

bool memEqlPost(u8* haystack)
{
	// NOTE(louis): the caller has to ensure that the size of the haystack is at least 
	// as long as POST 
	return *haystack == POST_METHOD_NAME[0] 
		   && *(haystack + 1) == POST_METHOD_NAME[1]
		   && *(haystack + 2) == POST_METHOD_NAME[2]
		   && *(haystack + 3) == POST_METHOD_NAME[3];
}

bool memEqlHttpVersionPrefix(u8* haystack)
{
	// NOTE(louis): the caller has to ensure that the size of the haystack is at least 
	// as long as POST 
	return *haystack == HTTP_VERSION_PREFIX[0] 
		   && *(haystack + 1) == HTTP_VERSION_PREFIX[1]
		   && *(haystack + 2) == HTTP_VERSION_PREFIX[2]
		   && *(haystack + 3) == HTTP_VERSION_PREFIX[3]
		   && *(haystack + 4) == HTTP_VERSION_PREFIX[4];
}

u8* memFindCrlf(u8* haystack, usize haystackLen)
{
	for (int i = 0; i <= haystackLen - CRLF_LEN; ++i, ++haystack)
	{
		if (*haystack == CRLF[0]
			&& *(haystack + 1) == CRLF[1])
		{
			return haystack;
		}
	}

	return NULL;
}


bool memEql(u8* a, u8* b, usize len)
{
	for (int i = 0; i < len; ++i, ++a, ++b)
	{
		if (*a != *b)
		{
			return false;
		}
	}

	return true;
}

u8* memFindChr(u8* haystack, usize haystackLen, u8 needle)
{
	for (int i = 0; i < haystackLen; ++i, ++haystack)
	{
		if (*haystack == needle)
		{
			return haystack;
		}
	}

	return NULL;
}

u8* memFindMem(u8* haystack, usize haystackLen, u8* needle, usize needleLen)
{
	for (int i = 0; i <= haystackLen - needleLen; ++i, ++haystack)
	{
		if (memEql(haystack, needle + 1, needleLen))
		{
			return haystack;
		}
	}

	return NULL;
}

