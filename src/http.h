#ifndef HTTP_H 
#define HTTP_H 

#include "mem.h"
#include "types.h"
#include "http_header_map.h"

constexpr u32 MAX_HTTP_HEADER_SIZE = 8 * 1024;
constexpr u32 STATUS_CODE_OFFSET = 9; 

constexpr u16 OK = 200;
constexpr u16 BAD_REQUEST = 400;
constexpr u16 NOT_IMPLEMENTED = 501;

constexpr u8 OK_RESPONSE[] = { 'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', ' ', '\r', '\n', '\r', '\n' };
constexpr u8 BAD_REQUEST_RESPONSE[] = { 'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '4', '0', '0', ' ', '\r', '\n', '\r', '\n' };
constexpr u8 NOT_IMPLEMENTED_RESPONSE[] = { 'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '5', '0', '1', ' ', '\r', '\n', '\r', '\n' };

constexpr u16 DEFAULT_RESPONSE_LEN = sizeof(OK_RESPONSE);

constexpr u8 TRANSFER_ENCODING_HEADER_NAME[] = { 'T', 'r', 'a', 'n', 's', 'f', 'e', 'r', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g' };
constexpr u8 CONTENT_LENGTH_HEADER_NAME[] = { 'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h' };
constexpr u8 HOST_HEADER_NAME[] = { 'H', 'o', 's', 't' };

constexpr string TRANSFER_ENCODING_STRING = 
{
	(u8*) TRANSFER_ENCODING_HEADER_NAME,
	sizeof(TRANSFER_ENCODING_HEADER_NAME)
};

constexpr string CONTENT_LENGTH_STRING = 
{
	(u8*) CONTENT_LENGTH_HEADER_NAME,
	sizeof(CONTENT_LENGTH_HEADER_NAME)
};

constexpr string HOST_STRING = 
{
	(u8*) HOST_HEADER_NAME,
	sizeof(HOST_HEADER_NAME)
};

constexpr u64 TRANSFER_ENCODING_HASH = comptimeHash(TRANSFER_ENCODING_HEADER_NAME, sizeof(TRANSFER_ENCODING_HEADER_NAME));
constexpr u64 CONTENT_LENGTH_HASH = comptimeHash(CONTENT_LENGTH_HEADER_NAME, sizeof(CONTENT_LENGTH_HEADER_NAME));
constexpr u64 HOST_HEADER_HASH = comptimeHash(HOST_HEADER_NAME, sizeof(HOST_HEADER_NAME));

typedef u16 http_status_code;

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

u8* parseHeader(u16* errorCode, http_header*, u8*, u32);
const u8* lookupResponse(http_status_code);
#endif
