#include "pool_allocator.h"
#include <assert.h>
#include <stddef.h>

void init(pool_allocator* alloc, void* startAddr, usize len, usize chunkSize)
{
	if (chunkSize < sizeof(pool_node))
		assert(!"Invalid chunk size.");

	if (len < chunkSize)
		assert(!"Invalid length and chunk size provided.");

	alloc->startAddr = (uintptr) startAddr;
	alloc->len = len;
	alloc->chunkSize = chunkSize;
	alloc->head = NULL;
	for (uintptr addr = (uintptr) startAddr; addr < (uintptr) startAddr + len; addr += chunkSize)
	{
		pool_node* node = (pool_node*) addr;
		node->next = alloc->head;
		alloc->head = node;
	}
}

void* allocate(pool_allocator* alloc)
{
	if (!alloc->head)
		return (void*) -1;

	pool_node* ptr = alloc->head;
	alloc->head = ptr->next;
	return (void*) ptr;
}

void free(pool_allocator* alloc, void* ptr)
{
	pool_node* node = (pool_node*) ptr;
	node->next = alloc->head;
	alloc->head = node->next;
}
