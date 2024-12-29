#ifndef ARTICLES_H
#define ARTICLES_H

#include <pthread.h>
#include "types.h"
#include "file_cache.h"

constexpr u8 TITLE_SIZE = 128;
constexpr u16 PREVIEW_SIZE = 256;
constexpr u8 MAX_SUBSCRIBERS = 16;
constexpr u8 MAX_ARTICLE_PREVIEWS = 16;

#ifndef ARTICLES_PATH
#define ARTICLES_PATH "/var/www/static/articles/"
#endif

struct article_preview
{
	char title[TITLE_SIZE];
	char preview[PREVIEW_SIZE];
};

struct articles_resource
{
	pthread_mutex_t* fileCacheGuard;
	char pathBuffer[sizeof(ARTICLES_PATH) + FILE_PATH_LEN - 1];

	file_handle_entry* subscribers[MAX_SUBSCRIBERS];
	u32 subscribersLen;

	article_preview articlePreviews[MAX_ARTICLE_PREVIEWS];
	u32 articlePreviewsLen;
};

void init(articles_resource*, pthread_mutex_t*);
// i16 destroy(articles_resource*);
i16 addSubscriber(file_handle_entry*);
i16 putArticle(articles_resource*, char*, usize, char*, usize);

#endif
