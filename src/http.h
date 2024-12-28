#ifndef HTTP_H 
#define HTTP_H 

#include "mem.h"
#include "types.h"
#include "http_header_map.h"

#define CORRUPTED_HEADER -1

#define DEFINE_STRING(name, value) \
constexpr string name = \
{ \
	(char*) value, \
	sizeof(value) - 1 \
}; \

DEFINE_STRING(ADD_ARTICLE_ROUTE, "/add-article");
DEFINE_STRING(NEWSLETTER_SIGNUP_ROUTE, "/newsletter-signup");

constexpr u32 MAX_HTTP_MESSAGE_LEN = 1024 * 1024;
constexpr u32 MAX_HTTP_HEADER_LEN = 8 * 1024;

constexpr char HTTP_VERSION_1_1[] = "1.1 ";
constexpr u32 HTTP_VERSION_1_1_LEN = sizeof(HTTP_VERSION_1_1) - 1;

constexpr u16 OK = 200;
constexpr u16 BAD_REQUEST = 400;
constexpr u16 NOT_FOUND = 404;
constexpr u16 TOO_LARGE = 413;
constexpr u16 NOT_IMPLEMENTED = 501;

constexpr char OK_RESPONSE[] = "HTTP/1.1 200 ";
constexpr char BAD_REQUEST_RESPONSE[] = "HTTP/1.1 400 ";
constexpr char NOT_FOUND_RESPONSE[] = "HTTP/1.1 404 ";
constexpr char TOO_LARGE_RESPONSE[] = "HTTP/1.1 413 ";
constexpr char NOT_IMPLEMENTED_RESPONSE[] = "HTTP/1.1 501 ";
constexpr u32 DEFAULT_RESPONSE_LEN = sizeof(OK_RESPONSE) - 1;

DEFINE_STRING(ZERO_LEN, "0");
DEFINE_STRING(TRANSFER_ENCODING_HEADER_NAME, "Transfer-Encoding");
DEFINE_STRING(CONTENT_LENGTH_HEADER_NAME, "Content-Length"); 
DEFINE_STRING(HOST_HEADER_NAME, "Host");
DEFINE_STRING(AUTH_HEADER_NAME, "Authorization");


constexpr u64 TRANSFER_ENCODING_HASH = hash((string*) &TRANSFER_ENCODING_HEADER_NAME);
constexpr u64 CONTENT_LENGTH_HASH = hash((string*) &CONTENT_LENGTH_HEADER_NAME);
constexpr u64 HOST_HEADER_HASH = hash((string*) &HOST_HEADER_NAME);
constexpr u64 AUTH_HEADER_HASH= hash((string*) &AUTH_HEADER_NAME);

typedef u16 http_status_code;

enum http_method 
{
	GET,
	POST,
	PUT
};

struct http_version 
{
	u8 major;
	u8 minor;
};

struct http_request
{
	http_method method;
	string requestTarget;
	http_version version;
	http_header_map headerMap;
	string messageBody;
};

struct http_response 
{
	http_status_code statusCode;
	char* reason;
	http_version version;
	http_header_map headerMap;
	string messageBody;
};

struct buffered_response_writer
{
	char buffer[MAX_HTTP_MESSAGE_LEN];
	usize nRemaining;
	usize offset;
};

void initEmptyResponse(http_response*, http_status_code);
i16 parseHttpRequest(u16* errorCode, http_request*, char*, u32);
const char* lookupStatusLine(http_status_code);
i16 serializeResponse(string*, http_response*, arena_allocator*);

void init(buffered_response_writer*);
void reset(buffered_response_writer*);
i16 pushChar(buffered_response_writer*, char);
i16 pushStr(buffered_response_writer*, char*);
i16 pushString(buffered_response_writer*, string*);

#endif
