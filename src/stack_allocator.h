#ifndef STACK_ALLOCATOR_H
#define STACK_ALLOCATOR_H

#include <stddef.h>
#include "types.h"

struct item
{
	item* prev;
	usize len;	
	void* addr;
};

struct stack_allocator
{
	void* addr;
	void* endAddr;
	item* head;
};

void init(stack_allocator*, void*, usize);
void* allocate(stack_allocator*, usize);
void free(stack_allocator*);
void reset(stack_allocator*);

#endif
