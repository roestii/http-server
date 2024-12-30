#ifndef ARTICLES_H
#define ARTICLES_H

#include <pthread.h>
#include "types.h"
#include "mem.h"

constexpr u8 MAX_TITLE_LENGTH = 128;
constexpr u16 MAX_PREVIEW_LENGTH = 256;
constexpr u8 MAX_SUBSCRIBERS = 16;
constexpr u8 MAX_ARTICLE_PREVIEWS = 16;

#ifndef ARTICLES_PATH
#define ARTICLES_PATH "/var/www/static/articles/"
#endif

struct article_preview
{
	char title[MAX_TITLE_LENGTH];
	char preview[MAX_PREVIEW_LENGTH];
};

struct articles_resource
{
	pthread_mutex_t guard;
	char pathBuffer[sizeof(ARTICLES_PATH) + FILE_PATH_LEN - 1];
	article_preview articlePreviews[MAX_ARTICLE_PREVIEWS];
	u32 articlePreviewsLen;
};

i16 init(articles_resource*); 
i16 destroy(articles_resource*);
i16 putArticle(articles_resource*, char*, usize, char*, usize);

#endif
