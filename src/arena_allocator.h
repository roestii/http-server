#ifndef ARENA_ALLOCATOR_H
#define ARENA_ALLOCATOR_H

#include "types.h"

struct arena_allocator
{
	void* start;
	usize len;
	usize offset;
};

i16 init(arena_allocator*, usize);
i16 destroy(arena_allocator*);

void reset(arena_allocator*);
void* allocate(arena_allocator*, usize);
#endif