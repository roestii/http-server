#ifndef PARSER_H
#define PARSER_H

#include "types.h"

#define MAX_HTTP_HEADER_SIZE 8 * 1024

enum http_method 
{
	GET,
	POST
};

i32 parseHeader(u8*, u32);

#endif
