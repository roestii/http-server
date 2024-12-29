#include "file_cache.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

i16 init(file_cache* fileCache, arena_allocator* fileCacheMemory)
{
	if (pthread_mutex_init(&fileCache->guard, NULL) == -1)
		return -1;
	fileCache->fileCacheMemory = fileCacheMemory;
	fileCache->len = 0;

	return 0;
}

i16 destroy(file_cache* fileCache)
{
	return pthread_mutex_destroy(&fileCache->guard);
}

i16 get(file_handle_entry* result, file_cache* fileCache, string* fileName)
{
	i16 retval = 0;
	if (fileName->len > FILE_PATH_LEN)
		return -1;

	if (pthread_mutex_lock(&fileCache->guard) == -1)
		return -1;

	file_handle_entry* handle = fileCache->handles;
	for (int i = 0; i < fileCache->len; ++i, ++handle)
	{
		if (memEql(fileName->ptr, handle->fileName, fileName->len))
		{
			*result = *handle;
			retval = 1;
			break;
		}
	}

	if (pthread_mutex_unlock(&fileCache->guard) == -1)
		return -1;

	return retval;
}

i16 push(file_cache* fileCache, char* fileName, usize fileNameLen)
{
	if (fileNameLen >= FILE_PATH_LEN)
		return -1;

	if (fileCache->len == MAX_STATIC_FILES)
		return -1;

	if (pthread_mutex_lock(&fileCache->guard) == -1)
		return -1;

	file_handle_entry* entry = fileCache->handles + fileCache->len;

	char pathBuf[sizeof(STATIC_FILE_DIR) + FILE_PATH_LEN - 1];
	memCpy(pathBuf, (char*) STATIC_FILE_DIR, sizeof(STATIC_FILE_DIR) - 1);
	memCpy(pathBuf + sizeof(STATIC_FILE_DIR) - 1, fileName, fileNameLen);

	i32 fd = open(pathBuf, O_RDONLY);
	if (fd == -1)
		return -1;

	struct stat fileStat;
	if (stat(pathBuf, &fileStat) == -1)
		return -1;

	char* contentHandle = (char*) allocate(fileCache->fileCacheMemory, sizeof(char) * fileStat.st_size);
	if (contentHandle == (char*) -1)
		return -1;

	i32 n = read(fd, contentHandle, fileStat.st_size);
	if (n != fileStat.st_size)
		return -1;

	memCpy(entry->fileName, fileName, fileNameLen);
	entry->contentHandle = contentHandle;
	entry->fileSize = fileStat.st_size;
	++fileCache->len;

	if (pthread_mutex_unlock(&fileCache->guard) == -1)
		return -1;

	return 0;
}

i16 buildStaticCache(file_cache* result)
{
	DIR* staticDir = opendir(STATIC_FILE_DIR);
	if (!staticDir)
		return -1;

	file_handle_entry* currentHandle = result->handles;

	char pathBuf[sizeof(STATIC_FILE_DIR) + FILE_PATH_LEN - 1];
	memCpy(pathBuf, (char*) STATIC_FILE_DIR, sizeof(STATIC_FILE_DIR) - 1);

	dirent* currentEntry = readdir(staticDir);
	for (int i = 0; currentEntry && i < MAX_STATIC_FILES; 
		 ++i, currentEntry = readdir(staticDir)) 
	{
		if (currentEntry->d_type != DT_REG)
			continue;

		// TODO(louis): Introduce a proper string library for copying.
		memCpy(pathBuf + sizeof(STATIC_FILE_DIR) - 1, 
		 	   currentEntry->d_name, FILE_PATH_LEN);

		struct stat fileStat;
		if (stat(pathBuf, &fileStat) == -1)
			return -1;


		i16 fileDescriptor = open(pathBuf, O_RDONLY);
		if (fileDescriptor == -1)
			return -1;

		// TODO(louis): we could leave some entries empty if they don't fit and put 
		// them back into the cache when they were used (lru).
		char* contentHandle = (char*) allocate(result->fileCacheMemory, fileStat.st_size * sizeof(char));
		if (contentHandle == (void*) -1)
			return -1;
		i16 readBytes = read(fileDescriptor, (void*) contentHandle, fileStat.st_size * sizeof(char));

		if (readBytes != fileStat.st_size * sizeof(char))
			return -1;

		memCpy(currentHandle->fileName, currentEntry->d_name, FILE_PATH_LEN);
		currentHandle->contentHandle = contentHandle;
		currentHandle->fileSize = fileStat.st_size;
		++currentHandle;
		++result->len;
	}

	return 0;
}
