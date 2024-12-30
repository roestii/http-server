#ifndef LINKED_LIST_ALLOCATOR_H
#define LINKED_LIST_ALLOCATOR_H

#include "arena_allocator.h"

struct block
{
	void* startAddr;
	usize len;
};

struct linked_list_allocator
{
	block* head;
	block* tail;
};

i16 init(linked_list_allocator*, arena_allocator*, usize);
void* allocate(linked_list_allocator*, usize);
void free(linked_list_allocator*, void*);
#endif
