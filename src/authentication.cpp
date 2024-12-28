#include "authentication.h"

i16 hexdecodeSHA256(u8* digestBuf, char* digestStr)
{
	// NOTE(louis): The caller has to ensure that the length of the provided buffers match the SHA256_DIGEST_LENGTH
	
	for (int i = 0; i < 2 * SHA256_DIGEST_LENGTH; i += 2, digestStr += 2, ++digestBuf)
	{
		u8 idxA = *digestStr - '0';
		u8 idxB = *(digestStr + 1) - '0';

		if (idxA < 0 || idxA >= sizeof(HEX_LOOKUP_TABLE))
			return -1;

		if (idxB < 0 || idxB >= sizeof(HEX_LOOKUP_TABLE))
			return -1;
		
		*digestBuf = HEX_LOOKUP_TABLE[idxA] * 16 + HEX_LOOKUP_TABLE[idxB];
	}

	return 0;
}

bool authenticate(string* data, u8* hash)
{
	// NOTE(louis): The caller has to ensure that the hash has the size of a SHA256 digest
	u8 mdBuf[SHA256_DIGEST_LENGTH];
	SHA256((const u8*) data->ptr, data->len, mdBuf);

	// TODO(louis): make an optimized sha256 digest compare
	return memEql((char*) mdBuf, (char*) hash, SHA256_DIGEST_LENGTH);
}
