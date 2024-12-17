#ifndef HTTP_HEADER_MAP_H
#define HTTP_HEADER_MAP_H

#include "mem.h"
#include "types.h"
#include "arena_allocator.h"

enum bucket_tag
{
	INITIALIZED,
	EMPTY,
	TOMBSTONE
};

struct http_header_bucket 
{
	// for the round robin implementation
	u32 hash;
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

i16 init(http_header_map*, arena_allocator*, u32);
void clear(http_header_map*);

i16 insert(http_header_map*, string*, string*);
i16 get(string*, http_header_map*);
i16 del(http_header_map*, string*);

#endif
