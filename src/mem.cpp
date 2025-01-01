#include "mem.h"

void memCpy(char* dest, char* src, usize len)
{
	for (int i = 0; i < len; ++i, ++dest, ++src)
	{
		*dest = *src;
	}
}

bool memEql(char* a, char* b, usize len)
{
	for (int i = 0; i < len; ++i, ++a, ++b)
	{
		if (*a != *b)
			return false;
	}

	return true;
}

bool stringEql(string* a, string* b)
{
	if (a->len != b->len)
		return false;

	return memEql(a->ptr, b->ptr, a->len);
}

char* memFindChr(char* haystack, usize haystackLen, u8 needle)
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

char* memFindMem(char* haystack, usize haystackLen, char* needle, usize needleLen)
{
	for (int i = 0; i <= haystackLen - needleLen; ++i, ++haystack)
	{
		if (memEql(haystack, needle, needleLen))
		{
			return haystack;
		}
	}

	return NULL;
}

