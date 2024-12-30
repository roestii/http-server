#ifndef HASH_H
#define HASH_H

constexpr u64 HASH_P = 53;
constexpr u64 HASH_M = 1e9 + 9;
constexpr u64 HASH_A = 0x678DDE6F; // knuth recommendation

constexpr u8 HORNER_CONSTANT = 3;

constexpr u32 HASH_TABLE_M = 256; // m = 2^p
constexpr u32 HASH_TABLE_P = 8;
constexpr u32 HASH_TABLE_Q = 16; // amount of right shifts

enum bucket_tag 
{
	INITIALIZED,
	EMPTY,
	TOMBSTONE,
};

constexpr u64 hash(string* value)
{
	// NOTE(louis): The caller has to ensure that this function is not called with a string 
	// of length zero.
	
	u32 minLen = HORNER_CONSTANT;
	if (value->len < minLen)
		minLen = value->len;

	char* lastPtr = value->ptr + value->len - 1;
	u64 h = *lastPtr;
	--lastPtr;
	for (int i = 0; i < minLen - 1; ++i, --lastPtr)
	{
		h = HASH_P * h + *lastPtr;
	}

	return (h * HASH_A >> HASH_TABLE_Q) & (HASH_TABLE_M - 1);
}

constexpr u64 strnHash(char* value, usize len)
{
	// NOTE(louis): The caller has to ensure that this function is not called with a string 
	// of length zero.
	
	char* endPtr = memFindChr(value, len, '\0');
	if (!endPtr)
		endPtr = value + len;

	u32 minLen = HORNER_CONSTANT;
	if (endPtr - value < minLen)
		minLen = endPtr - value;

	char* lastPtr = endPtr - 1;
	u64 h = *lastPtr;
	--lastPtr;
	for (int i = 0; i < minLen - 1; ++i, --lastPtr)
	{
		h = HASH_P * h + *lastPtr;
	}

	return (h * HASH_A >> HASH_TABLE_Q) & (HASH_TABLE_M - 1);
}

#endif
