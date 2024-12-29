#ifndef FILE_CACHE_H
#define FILE_CACHE_H

#include <dirent.h>
#include <pthread.h>

#include "types.h"
#include "mem.h"
#include "arena_allocator.h"

constexpr u16 MAX_STATIC_FILES = 128;
constexpr u16 FILE_PATH_LEN = 256;
constexpr char STATIC_FILE_DIR[] = "/var/www/static/";

struct file_handle_entry
{
	char fileName[FILE_PATH_LEN];
	char* contentHandle;
	usize fileSize;
};

// TODO(louis): 
// 		- Consider making this a hashmap
// 		- what if a file didn't fit into the cache at initialization, 
// 		  then we return 404 at the moment which is not what we want...
// 		- we probably need a general purpose allocator for this
// 		- introduce the concept of present and not present entries

struct file_cache
{
	pthread_mutex_t guard;
	u32 len;
	file_handle_entry handles[MAX_STATIC_FILES];
	arena_allocator* fileCacheMemory;
};

i16 init(file_cache*, arena_allocator*);
i16 destroy(file_cache*);
i16 get(file_handle_entry*, file_cache*, string*);
i16 push(file_cache*, char*, usize);
i16 buildStaticCache(file_cache*);
#endif 
