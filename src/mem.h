#ifndef MEM_H
#define MEM_H

#include "types.h"
#include <stddef.h>

struct string 
{
	char* ptr;
	isize len;
};

#define FILE_PATH_LEN 256

constexpr char HTTP_VERSION_PREFIX[] = "HTTP/";
constexpr u32 HTTP_VERSION_PREFIX_LEN = sizeof(HTTP_VERSION_PREFIX) - 1;

constexpr string HTTP_VERSION_PREFIX_STRING =
{
	(char*) HTTP_VERSION_PREFIX,
	HTTP_VERSION_PREFIX_LEN
};

constexpr char CRLF[] = "\r\n";
constexpr u32 CRLF_LEN = sizeof(CRLF) - 1;

constexpr char SP = ' ';

constexpr char GET_METHOD_NAME[] = "GET";
constexpr char POST_METHOD_NAME[] = "POST";
constexpr char PUT_METHOD_NAME[] = "PUT";

constexpr u32 GET_METHOD_NAME_LEN = sizeof(GET_METHOD_NAME) - 1;
constexpr u32 POST_METHOD_NAME_LEN = sizeof(POST_METHOD_NAME) - 1;
constexpr u32 PUT_METHOD_NAME_LEN = sizeof(PUT_METHOD_NAME) - 1;


bool stringEql(string*, string*);

bool memEql(char*, char*, usize);
bool memEqlGet(char*);
bool memEqlPost(char*);
bool memEqlPut(char*);
bool memEqlCrlf(char*);
bool memEqlHttpVersionPrefix(char*);

char* memFindChr(char*, usize, u8);
char* memFindCrlf(char*, usize);
char* memFind2Crlf(char*, usize);
char* memFindMem(char*, usize, char*, usize);

void memCpy(char*, char*, usize);

#endif
