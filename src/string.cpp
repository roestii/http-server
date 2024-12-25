#include "string.h"

void u64ToStr(string* result, arena_allocator* alloc, u64 x)
{
	i16 lzcnt = __builtin_clzll(x);
	u8 nDecimals = LZCNT_N_DECIMALS_TABLE[lzcnt];
	char* buffer = (char*) allocate(alloc, (nDecimals + 1) * sizeof(char));
	char* bufferEnd = buffer + nDecimals - 1;

	for (int i = 0; i < nDecimals; ++i, --bufferEnd)
	{
		usize n = x / 10;
		u8 remainder = x - (10 * n);
		*bufferEnd = remainder + '0';
		x = n;
	}

	result->ptr = buffer;
	result->len = nDecimals;
}

i16 strToU64(u64* result, string* str)
{
	u64 res = 0;
	u64 factor = 1;
	char* currentChar = str->ptr + str->len - 1;
	for (;currentChar >= str->ptr; --currentChar, factor *= 10)
	{
	  	u8 digit = *currentChar - '0';
		if (digit < 0 || digit > 9)
			return -1;

		res += factor * digit;
	}

	*result = res;
	return 0;
}
