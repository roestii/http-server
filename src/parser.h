#ifndef PARSER_H
#define PARSER_H

#include "types.h"

#define MAX_HTTP_HEADER_SIZE 8 * 1024


enum http_method 
{
	GET,
	POST
};

struct http_version 
{
	u8 major;
	u8 minor;
};

struct http_header_map_entry 
{
	u8* headerName;
	usize headerNameLen;
	u8* headerValue;
	usize headerValueLen;
};

struct http_header_map
{
};

struct http_header 
{
	http_method httpMethod;
	u8* requestTarget;
	usize requestTargetLen;
	http_version httpVersion;
	http_header_map httpHeaderMap;
};

i16 parseHeader(http_header*, u8*, u32);

#endif
