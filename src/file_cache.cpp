#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "file_cache.h"
#include "string.h"


/* i16 loadFileWithEvict(file_cache* fileCache, file_bucket* targetBucket)
{
	i16 retval = 0;
	char pathBuf[sizeof(STATIC_FILE_DIR) + FILE_PATH_LEN - 1];
	memCpy(pathBuf, (char*) STATIC_FILE_DIR, sizeof(STATIC_FILE_DIR) - 1);
	memCpy(pathBuf + sizeof(STATIC_FILE_DIR) - 1, targetBucket->fileName, FILE_PATH_LEN);

	i32 fd = open(pathBuf, O_RDONLY);
	if (fd == -1)
		return -1;

	struct stat fileStat;
	if (fstat(fd, &fileStat) == -1)
	{
		retval = -1;
		goto close_fd;
	}

	{
		file_bucket* currentBucket = fileCache->buckets;
		for (int i = 0; i < HASH_TABLE_M; ++i, ++currentBucket)
		{
			if (currentBucket->status != CACHED)
				continue;

			if (currentBucket->contentLen >= fileStat.st_size)	
			{
				free(fileCache->alloc, currentBucket->content);
				currentBucket->status = UNCACHED;
				targetBucket->content = (char*) allocate(fileCache->alloc, sizeof(char) * fileStat.st_size);
				if (targetBucket->content == (char*) -1)
					assert(!"There should be enough room for the allocation by now.");

				if (read(fd, targetBucket->content, fileStat.st_size) != fileStat.st_size)
					assert(!"Could not read entire file into cache.");

				targetBucket->contentLen = fileStat.st_size;
				targetBucket->status = CACHED;

				retval = 1;
				break;
			}
		}
	}
	
close_fd:
	if (close(fd) == -1)
		return -1;

	return retval;
} */

i32 loadFile(char** content, char* filePath, arena_allocator* alloc)
{
	i16 retval = 0;
	char pathBuf[sizeof(STATIC_FILE_DIR) + FILE_PATH_LEN - 1];
	memCpy(pathBuf, (char*) STATIC_FILE_DIR, sizeof(STATIC_FILE_DIR) - 1);
	memCpy(pathBuf + sizeof(STATIC_FILE_DIR) - 1, filePath, FILE_PATH_LEN);

	i32 fd = open(pathBuf, O_RDONLY);
	if (fd == -1)
		return -1;

	struct stat fileStat;
	if (fstat(fd, &fileStat) == -1)
	{
		retval = -1;
		goto close_fd;
	}
	
	*content = (char*) allocate(alloc, sizeof(char) * fileStat.st_size);
	if (*content == (char*) -1)
		assert(!"File does not fit into the cache");

	if (read(fd, *content, fileStat.st_size) != fileStat.st_size)
	{
		retval = -1;
		goto close_fd;
	}

	retval = fileStat.st_size;

close_fd:
	if (close(fd) == -1)
		return -1;

	return retval;
}

i16 init(file_cache* fileCache, arena_allocator* alloc)
{
	if (pthread_mutex_init(&fileCache->guard, NULL) == -1)
		return -1;
	fileCache->alloc = alloc;
	fileCache->len = 0;
	// fileCache->minDIB = -1;
	fileCache->maxDIB = 0;

	file_bucket* currentBucket = fileCache->buckets;
	for (int i = 0; i < HASH_TABLE_M; ++i, ++currentBucket)
		currentBucket->tag = EMPTY;

	return 0;
}

// void clear(file_cache* file)
// {
// 	http_header_bucket* currentBucket = headerMap->buckets;
// 	for (int i = 0; i < HASH_TABLE_M; ++i, ++currentBucket)
// 		currentBucket->tag = EMPTY;
// }

i16 destroy(file_cache* fileCache)
{
	return pthread_mutex_destroy(&fileCache->guard);
}

i16 insert(file_cache* fileCache, char* fileName, 
		   char* content, u32 contentLen/*, cache_status status */)
{
	// NOTE(louis): The caller has to ensure that the fileName buffer pointed to by fileName is of size 256 (FILE_PATH_LEN)
	if (fileCache->len == HASH_TABLE_M)
		return -1;

	assert(pthread_mutex_lock(&fileCache->guard) == 0);

	file_bucket* buckets = fileCache->buckets;
	u32 key = strnHash(fileName, FILE_PATH_LEN);
	u32 probePosition = 0; /* fileCache->minDIB */
	// if (probePosition == -1)
	// 	probePosition = 0;
	for (;; ++probePosition)
	{
		u32 location = (key + probePosition) & (HASH_TABLE_M - 1);
		file_bucket* probeBucket = buckets + location;
		switch (probeBucket->tag)
		{
			case EMPTY:
			case TOMBSTONE:
			{
				memCpy(probeBucket->fileName, fileName, FILE_PATH_LEN);
				probeBucket->content = content;	
				probeBucket->contentLen = contentLen;
				probeBucket->key = key;	
				// probeBucket->status = status;
				probeBucket->tag = INITIALIZED;

				if (probePosition > fileCache->maxDIB)
					fileCache->maxDIB = probePosition;

				// if (fileCache->minDIB == -1 || probePosition < fileCache->minDIB)
				// 	fileCache->minDIB = probePosition;

				++fileCache->len;
				assert(pthread_mutex_unlock(&fileCache->guard) == 0);
				return 0;
			}
			case INITIALIZED:
			{
				// NOTE(louis): Calculate the distance to the initial bucket using pointers.
				u32 actualPosition = probeBucket - fileCache->buckets;
				u32 recordPosition = actualPosition - probeBucket->key;
				if (recordPosition < 0)
					recordPosition += HASH_TABLE_M;

				if (probePosition > recordPosition)
				{
					file_bucket tmpBucket = *probeBucket;
					memCpy(probeBucket->fileName, fileName, FILE_PATH_LEN);
					probeBucket->content = content;
					probeBucket->contentLen = contentLen;
					// probeBucket->status = status;
	  				probeBucket->key = key;	

					memCpy(fileName, tmpBucket.fileName, FILE_PATH_LEN);
					content = tmpBucket.content;
					contentLen = tmpBucket.contentLen;
					probePosition = recordPosition;
					// status = tmpBucket.status;
					key = tmpBucket.key;

					if (probePosition > fileCache->maxDIB)
						fileCache->maxDIB = probePosition;
				}

				break;
			}
		}
	}
}

bool fileNameCmp(string* a, char* b)
{
	// NOTE(louis): The caller has to ensure that b is of size FILE_PATH_LEN
	if (a->len >= FILE_PATH_LEN)
		return false;
	
	if (*(b + a->len) != '\0')
	  	return false;

	return memEql(a->ptr, b, a->len);
}

i16 get(file_bucket* result, file_cache* fileCache, string* fileName)
{
	if (fileName->len >= FILE_PATH_LEN)
		return 0;

	i16 retval = 0;
	assert(pthread_mutex_lock(&fileCache->guard) == 0);

	u32 key = hash(fileName);
	u32 probePosition = 0;
	// if (probePosition < 0)
	// 	probePosition = 0;
	for (;probePosition <= fileCache->maxDIB; ++probePosition)
	{
		u32 location = (key + probePosition) & (HASH_TABLE_M - 1);
		file_bucket* probeBucket = fileCache->buckets + location;

		switch (probeBucket->tag)
		{
			case INITIALIZED:
			{
				if (fileNameCmp(fileName, probeBucket->fileName))
				{ 
					/*
					if (probeBucket->status == UNCACHED)
					{
						if (loadFileWithEvict(fileCache, probeBucket) <= 0)
							assert(!"Cannot load file into cache");
					} 
					*/

					*result = *probeBucket;
					retval = 1;
					goto get_exit;
				}

				break;
			}
			case EMPTY: goto get_exit;
			case TOMBSTONE: break;
		}
	}

get_exit:
	assert(pthread_mutex_unlock(&fileCache->guard) == 0);
	return retval;
}

i16 buildStaticCache(file_cache* result)
{
	DIR* staticDir = opendir(STATIC_FILE_DIR);
	if (!staticDir)
		return -1;

	char pathBuf[sizeof(STATIC_FILE_DIR) + FILE_PATH_LEN - 1];
	memCpy(pathBuf, (char*) STATIC_FILE_DIR, sizeof(STATIC_FILE_DIR) - 1);

	dirent* currentEntry = readdir(staticDir);
	for (int i = 0; currentEntry && i < HASH_TABLE_M; 
		 ++i, currentEntry = readdir(staticDir)) 
	{
		if (currentEntry->d_type != DT_REG)
			continue;

		char* content;
		i32 contentLen = loadFile(&content, currentEntry->d_name, result->alloc);
		insert(result, currentEntry->d_name, content, contentLen/*, CACHED */);
	}

	return 0;
}
