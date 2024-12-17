#ifndef HTTP_H 
#define HTTP_H 

#include "mem.h"
#include "types.h"
#include "http_header_map.h"

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

struct http_header 
{
	http_method method;
	string requestTarget;
	http_version version;
	http_header_map headerMap;
};

i16 parseHeader(http_header*, u8*, u32);
#endif
