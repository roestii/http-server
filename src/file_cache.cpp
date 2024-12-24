#include "file_cache.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

void init(file_cache* fileCache)
{
	fileCache->len = 0;
}

i16 get(file_handle_entry* result, file_cache* fileCache, string* fileName)
{
	if (fileName->len > FILE_PATH_LEN)
		return -1;

	file_handle_entry* handle = fileCache->handles;
	for (int i = 0; i < fileCache->len; ++i, ++handle)
	{
		if (memEql(fileName->ptr, handle->fileName, fileName->len))
		{
			*result = *handle;
			return 1;
		}
	}

	return 0;
}

i16 buildStaticCache(file_cache* result, arena_allocator* alloc)
{
	result->len = 0;
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
		char* contentHandle = (char*) allocate(alloc, fileStat.st_size * sizeof(char));
		if (contentHandle == (void*) -1)
			return -1;
		i16 readBytes = read(fileDescriptor, (void*) contentHandle, fileStat.st_size * sizeof(char));

		if (readBytes != fileStat.st_size * sizeof(char))
			return -1;

		memCpy(currentHandle->fileName, currentEntry->d_name, FILE_PATH_LEN);
		currentHandle->contentHandle = contentHandle;
		currentHandle->fileSize = fileStat.st_size;
		++result->len;
	}

	return 0;
}
