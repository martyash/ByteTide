#ifndef BTYDE_CRYPT_SHA256
#define BTYDE_CRYPT_SHA256

#include <stdint.h>

#define SHA256_CHUNK_SZ (64)
#define SHA256_INT_SZ (8)
#define SHA256_DFTLEN (1024)
// sha256 is a hash function that takes data as bytes and hashes it 
// it processes data in chunks of 64 bytes hence CHUNK_SZ = 64 
// DFTLEN means the default length of the buffer 
//Original: https://github.com/LekKit/sha256/blob/master/sha256.h
struct sha256_compute_data { // holds 256 computation data 
	uint64_t data_size; // tracks the total size of the data being hashed
	uint32_t hcomps[SHA256_INT_SZ]; // An array of 32 bit integers holding hash values
	uint8_t last_chunk[SHA256_CHUNK_SZ]; // an array holding the last chunk of data 
	uint8_t chunk_size; // 
};

void sha256_calculate_chunk(struct sha256_compute_data* data,
		uint8_t chunk[SHA256_CHUNK_SZ]);

void sha256_compute_data_init(struct sha256_compute_data* data);

void sha256_update(struct sha256_compute_data* data,
		void* bytes, uint32_t size); 

void sha256_finalize(struct sha256_compute_data* data);


void sha256_output_hex(struct sha256_compute_data* data, 
		char hexbuf[SHA256_CHUNK_SZ]);

#endif

