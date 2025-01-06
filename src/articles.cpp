#include "articles.h"
#include "mem.h"

#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

i16 init(articles_resource* result)
{
	if (pthread_mutex_init(&result->guard, NULL) == -1)
		return -1;

	result->articlePreviewsLen = 0;
	memCpy(result->pathBuffer, (char*) ARTICLES_PATH, sizeof(ARTICLES_PATH) - 1);
	return 0;
}

i16 destroy(articles_resource* resource)
{
	return pthread_mutex_destroy(&resource->guard);
}

i16 parseArticlePreview(article_preview* result, char* buffer, usize len)
{
	char* titleEnd = memFindChr(buffer, len, '\n');
	if (!titleEnd)
		return -1;

	u32 titleLength = titleEnd - buffer - 1;
	if (titleLength == 0 || titleLength >= MAX_TITLE_LENGTH)
		return -1;

	u32 articleLength = len - (titleLength + 1);
	u32 previewLength = MAX_PREVIEW_LENGTH - 1;

	if (articleLength < previewLength)
		previewLength = articleLength;

	memCpy(result->title, buffer, titleLength);
	*(result->title + titleLength) = '\0';

	memCpy(result->preview, buffer, previewLength);
	*(result->preview + previewLength) = '\0';

	return 0;
}

i16 putArticle(articles_resource* resource,
			   char* fileName, usize fileNameLen,
			   char* buffer, usize bufferLen)
{
	if (fileNameLen >= FILE_PATH_LEN)
		return -1;

	assert(pthread_mutex_lock(&resource->guard) == 0);
	memCpy(resource->pathBuffer + sizeof(ARTICLES_PATH) - 1, fileName, fileNameLen);
	*(resource->pathBuffer + sizeof(ARTICLES_PATH) - 1 + fileNameLen) = '\0';

	i32 fd = open(resource->pathBuffer, O_CREAT | O_WRONLY | O_TRUNC);
	if (fd == -1)
		return -1;

	if (write(fd, buffer, bufferLen) != bufferLen)
		return -1;

	// if (mdToHtml(outFd, buffer, bufferLen) == -1)
	// 	return -1;

	// push(fileCache, outFd);

	// article_preview* preview = resource->articlePreviews + resource->articlePreviewsLen;
	// if (parseArticlePreview(preview, buffer, bufferLen) == -1)
	// 	return -1;

	// ++resource->articlePreviewsLen;
	// file_handle_entry* currentSubscriber = resource->subscribers;
	// for (int i = 0; i < resource->subscribersLen; ++i, ++currentSubscriber)
	// 	update(currentSubscriber, preview);

	if (close(fd) == -1)
		return -1;

	assert(pthread_mutex_unlock(&resource->guard) == 0);

	return 0;
}
