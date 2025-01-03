#ifndef STRING_H
#define STRING_H

#include "types.h"
#include "mem.h"
#include "arena_allocator.h"

constexpr u8 LZCNT_N_DECIMALS_TABLE[] = 
{
	19, 19, 19, 19, 18, 18, 18, 17, 17, 17, 16, 16, 16, 16, 15, 15,
	15, 14, 14, 14, 13, 13, 13, 13, 12, 12, 12, 11, 11, 11, 10, 10,
	10, 10,  9,  9,  9,  8,  8,  8,  7,  7,  7,  7,  6,  6,  6,  5,
	 5,  5,  4,  4,  4,  4,  3,  3,  3,  2,  2,  2,  1,  1,  1,  1
};

void u64ToStr(string*, arena_allocator*, usize);
i16 strToU64(u64*, string*);
i16 strnCpy(char*, char*, usize);
#endif
