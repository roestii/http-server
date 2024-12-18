#ifndef HTTP_HEADER_MAP_H
#define HTTP_HEADER_MAP_H

#include "mem.h"
#include "types.h"
#include "arena_allocator.h"

constexpr u64 HASH_P = 53;
constexpr u64 HASH_M = 1e9 + 9;

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
	u32 capacity;
	arena_allocator* alloc;
	http_header_bucket* buckets;				
};

constexpr u64 comptimeHash(const u8* ptr, usize len)
{
	u64 result = 0;
	u64 factor = 1;
	for (int i = 0; i < len; ++i, ++ptr)
	{
		result = (result + *ptr * factor) % HASH_M;
		factor *= factor % HASH_M;
	}

	return result;
}

i16 init(http_header_map*, arena_allocator*, u32);
void clear(http_header_map*);

i16 insert(http_header_map*, string*, string*);
i16 get(string*, http_header_map*, string*);
i16 getHash(string*, http_header_map*, u64, string*);
i16 del(http_header_map*, string*);
i16 delHash(http_header_map*, u64, string*);

#endif
