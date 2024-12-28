#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <openssl/sha.h>
#include "types.h"
#include "mem.h"

// TODO(louis): Make this not so hard coded...
// This is 1234, you know it know, and it is hard coded yay, but it won't stay that way (smiley)
constexpr u8 HEX_LOOKUP_TABLE[] = 
{
	 0,  1,  2,  3,  4,  5,  6, 7, 8,  9,
	 0,  0,  0,  0,  0,  0,  0, 0, 0,  0,
	 0,  0,  0,  0,  0,  0,  0, 0, 0,  0,
	 0,  0,  0,  0,  0,  0,  0, 0, 0,  0,
	 0,  0,  0,  0,  0,  0,  0, 0, 0, 10, 
	11, 12, 13, 14, 15
};

bool authenticate(string*, u8*);
i16 hexdecodeSHA256(u8*, char*);
#endif
