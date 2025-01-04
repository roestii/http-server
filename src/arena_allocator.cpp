#include <sys/mman.h>
#include <stddef.h>
#include "arena_allocator.h"

i16 init(arena_allocator* result, usize len)
{
	result->start = (uintptr) mmap(NULL, len, PROT_READ | PROT_WRITE, 
	 	 				 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if ((void*) result->start == MAP_FAILED)
		return -1;

	result->len = len;
	result->offset = 0;
	return 0;
} 

void consume(arena_allocator* result, arena_allocator* arena)
{
	result->start = arena->start + arena->offset;
	result->offset = 0;
	result->len = arena->len - arena->offset;
	arena->offset = arena->len;
}

i16 subarena(arena_allocator* result, arena_allocator* alloc, usize len)
{
	if (alloc->offset + len > alloc->len)
		return -1;

	result->start = alloc->start + alloc->offset;
	result->offset = 0;
	result->len = len;
	alloc->offset += len;
	return 0;
}

void reset(arena_allocator* alloc)
{
	alloc->offset = 0;
}

i16 destroy(arena_allocator* alloc)
{
	return munmap((void*) alloc->start, alloc->len);	
}

void* allocate(arena_allocator* alloc, usize len)
{
	if (alloc->offset + len > alloc->len)
		return (void*) -1;

	uintptr result = alloc->start + alloc->offset;
	alloc->offset += len;
	return (void*) result;
}
