#ifndef HTTP_HEADER_MAP_H
#define HTTP_HEADER_MAP_H

#include "mem.h"
#include "types.h"
#include "hash.h"

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
	// i32 minDIB;
	u32 maxDIB;

	u32 len;
	http_header_bucket buckets[HASH_TABLE_M];				
};

void init(http_header_map*);
void clear(http_header_map*);

i16 insert(http_header_map*, string*, string*);
i16 get(string*, http_header_map*, string*);
i16 getHash(string*, http_header_map*, u64, string*);
i16 del(http_header_map*, string*);
i16 delHash(http_header_map*, u64, string*);

#endif
