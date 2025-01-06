#include "http_header_map.h"

void init(http_header_map* result)
{
	result->len = 0;
	// result->minDIB = -1;
	result->maxDIB = 0;

	// TODO(louis): handle allocation error
	http_header_bucket* currentBucket = result->buckets;
	for (int i = 0; i < HASH_TABLE_M; ++i, ++currentBucket)
		currentBucket->tag = EMPTY;
}

void clear(http_header_map* headerMap)
{
	http_header_bucket* currentBucket = headerMap->buckets;
	for (int i = 0; i < HASH_TABLE_M; ++i, ++currentBucket)
		currentBucket->tag = EMPTY;

	headerMap->len = 0;
}

i16 insert(http_header_map* headerMap, string* fieldName, string* fieldValue)
{
	// TODO(louis): resize the table
	http_header_bucket* buckets = headerMap->buckets;

	if (headerMap->len == HASH_TABLE_M)
		return -1;

	// TODO(louis): consider using hashing by multiplication and a 
	// table size that is a power of two.
	u32 key = hash(fieldName);
	u32 probePosition = 0;
	// if (probePosition == -1)
	// 	probePosition = 0;
	for (;; ++probePosition)
	{
		u32 location = (key + probePosition) & (HASH_TABLE_M - 1);
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

				// if (headerMap->minDIB == -1 || probePosition < headerMap->minDIB)
				// 	headerMap->minDIB = probePosition;

				++headerMap->len;
				return 0;
			}
			case INITIALIZED:
			{
				// NOTE(louis): Calculate the distance to the initial bucket using pointers.
				u32 actualPosition = probeBucket - headerMap->buckets;
				u32 recordPosition = actualPosition - probeBucket->key;
				if (recordPosition < 0)
					recordPosition += HASH_TABLE_M;

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
	u32 key = hash(fieldName);
	u32 probePosition = 0;
	// if (probePosition < 0)
	// 	probePosition = 0;
	for (;probePosition <= headerMap->maxDIB; ++probePosition)
	{
		u32 location = (key + probePosition) & (HASH_TABLE_M - 1);
		http_header_bucket* probeBucket = headerMap->buckets + location;

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
	u32 key = hash(fieldName);
	u32 probePosition = 0;
	// if (probePosition < 0)
	// 	probePosition = 0;

	for (;probePosition <= headerMap->maxDIB; ++probePosition)
	{
		u32 location = (key + probePosition) & (HASH_TABLE_M - 1);
		http_header_bucket* probeBucket = headerMap->buckets + location;

		switch (probeBucket->tag)
		{
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
				break;
			case EMPTY:
				return 0;
		}
	}

	return 0;
}

i16 getHash(string* result, http_header_map* headerMap, u64 digest, string* fieldName)
{
	u32 key = digest & (HASH_TABLE_M - 1);
	u32 probePosition = 0;
	// if (probePosition < 0)
	// 	probePosition = 0;
	for (;probePosition <= headerMap->maxDIB; ++probePosition)
	{
		u32 location = (key + probePosition) & (HASH_TABLE_M - 1);
		http_header_bucket* probeBucket = headerMap->buckets + location;

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
	u32 key = digest & (HASH_TABLE_M - 1);
	u32 probePosition = 0;
	// if (probePosition < 0)
	// 	probePosition = 0;

	for (;probePosition <= headerMap->maxDIB; ++probePosition)
	{
		u32 location = (key + probePosition) & (HASH_TABLE_M - 1);
		http_header_bucket* probeBucket = headerMap->buckets + location;

		switch (probeBucket->tag)
		{
			case INITIALIZED:
			{
				if (stringEql(fieldName, &probeBucket->fieldName))
				{ 
					probeBucket->tag = TOMBSTONE;
					--headerMap->len;
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
