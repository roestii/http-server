#ifndef HTTP_HEADER_MAP_H
#define HTTP_HEADER_MAP_H

#include "mem.h"
#include "types.h"
#include "arena_allocator.h"

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
	TOMBSTONE
};

struct http_header_bucket 
{
	// for the round robin implementation
	u32 key;
	string fieldName;
	string fieldValue;
	bucket_tag tag;
};

struct http_header_map
{
	// for the round robin implementation
	i32 minDIB;
	u32 maxDIB;

	u32 len;
	http_header_bucket buckets[HASH_TABLE_M];				
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

void init(http_header_map*);
void clear(http_header_map*);

i16 insert(http_header_map*, string*, string*);
i16 get(string*, http_header_map*, string*);
i16 getHash(string*, http_header_map*, u64, string*);
i16 del(http_header_map*, string*);
i16 delHash(http_header_map*, u64, string*);

#endif
