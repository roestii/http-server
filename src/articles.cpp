#include "articles.h"
#include "string.h"
#include "file_cache.h"

#include <fcntl.h>
#include <unistd.h>

void init(articles_resource* result, pthread_mutex_t* fileCacheGuard)
{
	result->subscribersLen = 0;
	result->articlePreviewsLen = 0;
	result->fileCacheGuard = fileCacheGuard;
	memCpy(result->pathBuffer, (char*) ARTICLES_PATH, sizeof(ARTICLES_PATH) - 1);
}

i16 addSubscriber(articles_resource* resource, file_handle_entry* fileHandle)
{
	u32 nSubscribers = resource->subscribersLen;
	if (nSubscribers == MAX_SUBSCRIBERS)
		return -1;
	
	*(resource->subscribers + nSubscribers) = fileHandle;
	return 0;
}

i16 putArticle(articles_resource* resource, 
			   char* fileName, usize fileNameLen, 
			   char* buffer, usize bufferLen)
{
	if (fileNameLen >= FILE_PATH_LEN)
		return -1;

	if (pthread_mutex_lock(resource->fileCacheGuard) == -1)
		return -1;

	memCpy(resource->pathBuffer + sizeof(ARTICLES_PATH) - 1, fileName, fileNameLen);
	*(resource->pathBuffer + sizeof(ARTICLES_PATH) - 1 + fileNameLen) = '\0';

	i32 fd = open(resource->pathBuffer, O_CREAT | O_WRONLY | O_TRUNC);
	if (fd == -1)
		return -1;

	if (write(fd, buffer, bufferLen) != bufferLen)
		return -1;

	// TODO(louis):
	// 		- parse the article preview 
	// 		- convert markdown to html
	// 		- notify the subscribers

	if (close(fd) == -1)
		return -1;

	if (pthread_mutex_unlock(resource->fileCacheGuard) == -1)
		return -1;

	return 0;
}
