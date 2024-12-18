#ifndef MEM_H
#define MEM_H

#include "types.h"
#include <stddef.h>

constexpr u8 HTTP_VERSION_PREFIX[5] = { 'H', 'T', 'T', 'P', '/' };

const u8 CRLF[2] = { '\r', '\n' };
constexpr u32 CRLF_LEN = sizeof(CRLF);

const u8 SP = ' ';

constexpr u8 GET_METHOD_NAME[3] = { 'G', 'E', 'T' };
constexpr u8 POST_METHOD_NAME[4] = { 'P', 'O', 'S', 'T' };

constexpr u32 GET_METHOD_NAME_LEN = sizeof(GET_METHOD_NAME);
constexpr u32 POST_METHOD_NAME_LEN = sizeof(POST_METHOD_NAME);

struct string 
{
	u8* ptr;
	isize len;
};

bool stringEql(string*, string*);

bool memEql(u8*, u8*, usize);
bool memEqlGet(u8*);
bool memEqlPost(u8*);
bool memEqlCrlf(u8*);
bool memEqlHttpVersionPrefix(u8*);

u8* memFindChr(u8*, usize, u8);
u8* memFindCrlf(u8*, usize);
u8* memFind2Crlf(u8*, usize);
u8* memFindMem(u8*, usize, u8*, usize);

void memCpy(u8*, u8*, usize);

#endif
