#ifndef FILE_CACHE_H
#define FILE_CACHE_H

#include <dirent.h>
#include <pthread.h>

#include "types.h"
#include "mem.h"
#include "hash.h"
#include "pool_allocator.h"

constexpr char STATIC_FILE_DIR[] = "/var/www/static/";
#define MAX_FILE_SIZE 8 * 1024



// TODO(louis): what about cache eviction?
// enum cache_status
// {
// 	CACHED,
// 	UNCACHED,
// };

struct file_bucket 
{
	u32 key;
	bucket_tag tag;

	char fileName[FILE_PATH_LEN];
	char* content;
	usize contentLen;
	// cache_status status;
};

// TODO(louis): 
// 		- what if a file didn't fit into the cache at initialization, 
// 		  then we return 404 at the moment which is not what we want...
// 		- we probably need a general purpose allocator for this
// 		- introduce the concept of present and not present entries

struct file_cache
{
	pthread_mutex_t guard;

	// i32 minDIB;
	u32 maxDIB;
	u32 len;

	file_bucket buckets[HASH_TABLE_M];
	pool_allocator* alloc;
};

i16 init(file_cache*, pool_allocator*);
i16 destroy(file_cache*);
i16 get(file_bucket*, file_cache*, string*);
i16 insert(file_cache*, char*, usize, char*, usize);
i16 buildStaticCache(file_cache*);
#endif 
