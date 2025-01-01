#ifndef MEM_H
#define MEM_H

#include "types.h"
#include <stddef.h>

struct string 
{
	char* ptr;
	isize len;
};

#define DEFINE_STRING(name, value) \
constexpr string name = \
{ \
	(char*) value, \
	sizeof(value) - 1 \
}; \

// NOTE(louis): The caller has to ensures that the length of the haystack is at least the length of the literal.
#define CONST_MEMEQL(name, literal) \
bool name(char* haystack) \
{ \
	for (int i = 0; i < sizeof(literal) - 1; ++i, ++haystack) \
	{ \
		if (*haystack != literal[i]) \
	  		return false; \
	} \
	return true; \
} \

#define CONST_FINDMEM(name, literal) \
char* name(char* haystack, usize len) \
{ \
	for (int i = 0; i <= len - (sizeof(literal) - 1); ++i, ++haystack) \
	{ \
	  	char* tmp = haystack; \
	  	bool isEql = true; \
		for (int j = 0; j < sizeof(literal) - 1; ++j, ++tmp)  \
	  	{ \
	  		if (*tmp != literal[j]) \
	   		{ \
				isEql = false; \
	  			break; \
	  		} \
	  	} \
		if (isEql) \
			return haystack; \
	} \
	return NULL; \
} 

#define FILE_PATH_LEN 256

constexpr char CRLF[] = "\r\n";
constexpr u8 CRLF_LEN = sizeof(CRLF) - 1;

constexpr char SP = ' ';

constexpr char GET_METHOD_NAME[] = "GET";
constexpr char POST_METHOD_NAME[] = "POST";
constexpr char PUT_METHOD_NAME[] = "PUT";

constexpr u32 GET_METHOD_NAME_LEN = sizeof(GET_METHOD_NAME) - 1;
constexpr u32 POST_METHOD_NAME_LEN = sizeof(POST_METHOD_NAME) - 1;
constexpr u32 PUT_METHOD_NAME_LEN = sizeof(PUT_METHOD_NAME) - 1;


bool stringEql(string*, string*);
bool memEql(char*, char*, usize);
char* memFindChr(char*, usize, u8);
char* memFindMem(char*, usize, char*, usize);
void memCpy(char*, char*, usize);

#endif
