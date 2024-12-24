#include "stack_allocator.h"

void init(stack_allocator* alloc, void* addr, usize len)
{
	alloc->addr = addr;
	alloc->endAddr = addr + len;
	alloc->head = NULL;
}

void* allocate(stack_allocator* alloc, usize len)
{
	item* head = alloc->head;
	item* nextItem;
	if (head)
		nextItem = (item*) (head->addr + head->len); 
	else
		nextItem = (item*) alloc->addr; 

	nextItem->addr = (void*) (nextItem + 1);
	nextItem->len = len;

	if ((u8*) nextItem->addr + len >= alloc->endAddr)
		return (void*) -1;

	nextItem->prev = alloc->head;
	alloc->head = nextItem;
	return nextItem->addr;
}

void free(stack_allocator* alloc)
{
	item* head = alloc->head;
	if (head)
	{
		if (head->prev)
			alloc->head = head->prev;
		else
			alloc->head = NULL;
	}
}

void reset(stack_allocator* alloc)
{
	alloc->head = NULL;
}
