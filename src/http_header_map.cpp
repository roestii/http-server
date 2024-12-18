#include "http_header_map.h"

i16 init(http_header_map* result, arena_allocator* alloc, u32 capacity)
{
	result->alloc = alloc;
	result->capacity = capacity;
	result->len = 0;
	result->minDIB = -1;
	result->maxDIB = 0;

	// TODO(louis): handle allocation error
	http_header_bucket* buckets = (http_header_bucket*) allocate(alloc, capacity * sizeof(http_header_bucket));
	if (buckets == (void*) -1)
		return -1;

	http_header_bucket* currentBucket = buckets;
	for (int i = 0; i < capacity; ++i, ++currentBucket)
	{
		currentBucket->tag = EMPTY;
	}
	result->buckets = buckets;
	return 0;
}

void clear(http_header_map* headerMap)
{
	http_header_bucket* currentBucket = headerMap->buckets;
	for (int i = 0; i < headerMap->capacity; ++i, ++currentBucket)
	{
		if (currentBucket->tag != EMPTY)
			currentBucket->tag = EMPTY;
	}
}


u64 hash(string* value)
{
	u64 result = 0;
	u64 factor = 1;
	u8* valuePtr = value->ptr;
	for (int i = 0; i < value->len; ++i, ++valuePtr)
	{
		result = (result + *valuePtr * factor) % HASH_M;
		factor *= factor % HASH_M;
	}

	return result;
}

i16 insert(http_header_map* headerMap, string* fieldName, string* fieldValue)
{
	// TODO(louis): resize the table
	u32 tableCap = headerMap->capacity;
	http_header_bucket* buckets = headerMap->buckets;

	if (headerMap->len == tableCap)
		return -1;

	u32 key = hash(fieldName) % tableCap;
	u32 probePosition = headerMap->minDIB;
	if (probePosition == -1)
		probePosition = 0;
	for (;; ++probePosition)
	{
		u32 location = (key + probePosition) % tableCap;
		http_header_bucket* probeBucket = buckets + location;
		switch (probeBucket->tag)
		{
			case EMPTY:
			case TOMBSTONE:
			{
				probeBucket->fieldName = *fieldName;	
				probeBucket->fieldValue = *fieldValue;	
				probeBucket->key = key;	
				probeBucket->tag = INITIALIZED;

				if (probePosition > headerMap->maxDIB)
					headerMap->maxDIB = probePosition;

				if (headerMap->minDIB == -1 || probePosition < headerMap->minDIB)
					headerMap->minDIB = probePosition;

				++headerMap->len;
				return 0;
			}
			case INITIALIZED:
			{
				// NOTE(louis): If we encounter the same fieldValue we just insert another entry
				// Euclidean integer modulo
				u32 recordPosition = probeBucket->key % tableCap;
				if (recordPosition < 0)
					recordPosition += tableCap;

				if (probePosition > recordPosition)
				{
					http_header_bucket tmpBucket = *probeBucket;
					probeBucket->fieldName = *fieldName;
					probeBucket->fieldValue = *fieldValue;
	  				probeBucket->key = key;	

					*fieldName = tmpBucket.fieldName;
					*fieldValue = tmpBucket.fieldValue;
					probePosition = recordPosition;
					key = tmpBucket.key;

					if (probePosition > headerMap->maxDIB)
						headerMap->maxDIB = probePosition;
				}
				break;
			}
		}
	}
}

i16 get(string* result, http_header_map* headerMap, string* fieldName)
{
	u32 tableCap = headerMap->capacity;
	u32 key = hash(fieldName) % tableCap;
	u32 probePosition = headerMap->minDIB;
	if (probePosition < 0)
		probePosition = 0;
	for (;probePosition <= headerMap->maxDIB; ++probePosition)
	{
		u32 location = (key + probePosition) % tableCap;
		http_header_bucket* probeBucket = headerMap->buckets + key;

		switch (probeBucket->tag)
		{
			case INITIALIZED:
			{
				if (stringEql(fieldName, &probeBucket->fieldName))
				{ 
					*result = probeBucket->fieldValue;
					return 1;
				}
			}
			case EMPTY:
				return 0;
			case TOMBSTONE:
				break;
		}
	}

	return 0;
}

i16 del(http_header_map* headerMap, string* fieldName)
{
	u32 tableCap = headerMap->capacity;
	u32 key = hash(fieldName) % tableCap;
	u32 probePosition = headerMap->minDIB;
	if (probePosition < 0)
		probePosition = 0;

	for (;probePosition <= headerMap->maxDIB; ++probePosition)
	{
		u32 location = (key + probePosition) % tableCap;
		http_header_bucket* probeBucket = headerMap->buckets + key;

		switch (probeBucket->tag)
		{
			case EMPTY:
			{
				return 0;
			}
			case INITIALIZED:
			{
				if (stringEql(fieldName, &probeBucket->fieldName))
				{ 
					probeBucket->tag = TOMBSTONE;
					--headerMap->len;
					return 1;
				}
			}
			case TOMBSTONE:
			{
				break;
			}
		}
	}

	return 0;
}

i16 getHash(string* result, http_header_map* headerMap, u64 digest, string* fieldName)
{
	u32 tableCap = headerMap->capacity;
	u32 key = digest % tableCap;
	u32 probePosition = headerMap->minDIB;
	if (probePosition < 0)
		probePosition = 0;
	for (;probePosition <= headerMap->maxDIB; ++probePosition)
	{
		u32 location = (key + probePosition) % tableCap;
		http_header_bucket* probeBucket = headerMap->buckets + key;

		switch (probeBucket->tag)
		{
			case INITIALIZED:
			{
				if (stringEql(fieldName, &probeBucket->fieldName))
				{ 
					*result = probeBucket->fieldValue;
					return 1;
				}
			}
			case EMPTY:
				return 0;
			case TOMBSTONE:
				break;
		}
	}

	return 0;
}

i16 delHash(http_header_map* headerMap, u64 digest, string* fieldName)
{
	u32 tableCap = headerMap->capacity;
	u32 key = digest % tableCap;
	u32 probePosition = headerMap->minDIB;
	if (probePosition < 0)
		probePosition = 0;

	for (;probePosition <= headerMap->maxDIB; ++probePosition)
	{
		u32 location = (key + probePosition) % tableCap;
		http_header_bucket* probeBucket = headerMap->buckets + key;

		switch (probeBucket->tag)
		{
			case EMPTY:
			{
				return 0;
			}
			case INITIALIZED:
			{
				if (stringEql(fieldName, &probeBucket->fieldName))
				{ 
					probeBucket->tag = TOMBSTONE;
					--headerMap->len;
					return 1;
				}
			}
			case TOMBSTONE:
			{
				break;
			}
		}
	}

	return 0;
}
