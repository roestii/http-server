#ifndef POOL_ALLOCATOR_H
#define POOL_ALLOCATOR_H

#include "types.h"

struct pool_node
{
	pool_node* next;
};

struct pool_allocator
{
	uintptr startAddr;
	usize len;		
	usize chunkSize;
	pool_node* head;
};

void init(pool_allocator*, void*, usize, usize);
void* allocate(pool_allocator*);
void free(pool_allocator*, void*);

#endif 
