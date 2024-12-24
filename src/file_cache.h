#ifndef FILE_CACHE_H
#define FILE_CACHE_H

#include <dirent.h>
#include "types.h"
#include "mem.h"
#include "arena_allocator.h"

constexpr u16 MAX_STATIC_FILES = 16;
constexpr u16 FILE_PATH_LEN = 256;
constexpr char STATIC_FILE_DIR[] = "/var/www/static/";

struct file_handle_entry
{
	char fileName[FILE_PATH_LEN];
	char* contentHandle;
	usize fileSize;
};

// TODO(louis): Consider making this a hashmap
struct file_cache
{
	u32 len;
	file_handle_entry handles[MAX_STATIC_FILES];
};

void init(file_cache*);
i16 destroy(file_cache*);
i16 get(file_handle_entry*, file_cache*, string*);
i16 buildStaticCache(file_cache*, arena_allocator*);
#endif 
