#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <thread>
#include <mutex>
#include <iosfwd>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
using namespace std;

#define ROTL32(qword, n) ((qword) << (n) ^ ((qword) >> (32 - (n))))

const int BN = 64 * 640;

const uint8_t t[4][4] = {
	{ 'e', 'x', 'p', 'a' },
	{ 'n', 'd', ' ', '1' },
	{ '6', '-', 'b', 'y' },
	{ 't', 'e', ' ', 'k' }
};

const uint8_t o[4][4] = {
	{ 'e', 'x', 'p', 'a' },
	{ 'n', 'd', ' ', '3' },
	{ '2', '-', 'b', 'y' },
	{ 't', 'e', ' ', 'k' }
};

static void s20_quarterround(uint32_t *y0, uint32_t *y1, uint32_t *y2, uint32_t *y3) {
	*y1 ^= ROTL32(*y0 + *y3, 7);
	*y2 ^= ROTL32(*y1 + *y0, 9);
	*y3 ^= ROTL32(*y2 + *y1, 13);
	*y0 ^= ROTL32(*y3 + *y2, 18);
}

static void s20_doubleround(uint32_t *x) {
	s20_quarterround(&x[0], &x[4], &x[8], &x[12]);
	s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
	s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
	s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
	s20_quarterround(&x[0], &x[1], &x[2], &x[3]);
	s20_quarterround(&x[5], &x[6], &x[7], &x[4]);
	s20_quarterround(&x[10], &x[11], &x[8], &x[9]);
	s20_quarterround(&x[15], &x[12], &x[13], &x[14]);
}

static void s20_hash(uint8_t *seq) {
	uint32_t x[16], z[16], tmp[16];
	memcpy(tmp, seq, 64);
	memcpy(x, tmp, 64);
	memcpy(z, tmp, 64);
	s20_doubleround(z);
	z[0] += x[0]; z[1] += x[1]; z[2] += x[2]; z[3] += x[3]; z[4] += x[4]; z[5] += x[5]; z[6] += x[6]; z[7] += x[7]; z[8] += x[8]; z[9] += x[9]; z[10] += x[10]; z[11] += x[11]; z[12] += x[12]; z[13] += x[13]; z[14] += x[14]; z[15] += x[15];
	memcpy(seq, z, 64);
}


// The 16-byte (128-bit) key expansion function
static void s20_expand16(uint8_t *k, uint8_t *n, uint8_t *keystream) {
	memcpy(keystream, t[0], 4);
	memcpy(keystream + 20, t[1], 4);
	memcpy(keystream + 40, t[2], 4);
	memcpy(keystream + 60, t[3], 4);
	memcpy(keystream + 4, k, 16);
	memcpy(keystream + 44, k, 16);
	memcpy(keystream + 24, n, 16);
	s20_hash(keystream);
}

// The 32-byte (256-bit) key expansion function
static void s20_expand32(uint8_t *k, uint8_t *n, uint8_t *keystream) {
	memcpy(keystream, o[0], 4);
	memcpy(keystream + 20, o[1], 4);
	memcpy(keystream + 40, o[2], 4);
	memcpy(keystream + 60, o[3], 4);
	memcpy(keystream + 4, k, 16);
	memcpy(keystream + 44, k, 16);
	memcpy(keystream + 24, n, 16);
	s20_hash(keystream);
}


bool s20_crypt128(uint8_t *key, uint32_t buf_sec, uint8_t *buf) {
	uint8_t keystemp[64];
	uint8_t n[] = {0, 0, 0, 0, 7, 2, 7, 2, 0, 0, 0, 0, 0, 0, 0, 0};
	
	memcpy(n + 8, &buf_sec, 4);
	s20_expand16(key, n, keystemp);

	uint32_t tmp1[16], tmp2[16];
	memcpy(tmp1, buf, 64);
	memcpy(tmp2, keystemp, 64);
	tmp1[0] ^= tmp2[0]; tmp1[1] ^= tmp2[1]; tmp1[2] ^= tmp2[2]; tmp1[3] ^= tmp2[3]; tmp1[4] ^= tmp2[4]; tmp1[5] ^= tmp2[5]; tmp1[6] ^= tmp2[6]; tmp1[7] ^= tmp2[7]; tmp1[8] ^= tmp2[8]; tmp1[9] ^= tmp2[9]; tmp1[10] ^= tmp2[10]; tmp1[11] ^= tmp2[11]; tmp1[12] ^= tmp2[12]; tmp1[13] ^= tmp2[13]; tmp1[14] ^= tmp2[14]; tmp1[15] ^= tmp2[15];
	memcpy(buf, tmp1, 64);
	return true;
}

bool s20_crypt256(uint8_t *key, uint32_t buf_sec, uint8_t *buf) {
	uint8_t n[] = {0, 0, 0, 0, 7, 2, 7, 2, 0, 0, 0, 0, 0, 0, 0, 0};
	uint8_t keystemp[64];
	
	memcpy(n + 8, &buf_sec, 4);
	s20_expand32(key, n, keystemp);

	uint32_t tmp1[16], tmp2[16];
	memcpy(tmp1, buf, 64);
	memcpy(tmp2, keystemp, 64);
	tmp1[0] ^= tmp2[0]; tmp1[1] ^= tmp2[1]; tmp1[2] ^= tmp2[2]; tmp1[3] ^= tmp2[3]; tmp1[4] ^= tmp2[4]; tmp1[5] ^= tmp2[5]; tmp1[6] ^= tmp2[6]; tmp1[7] ^= tmp2[7]; tmp1[8] ^= tmp2[8]; tmp1[9] ^= tmp2[9]; tmp1[10] ^= tmp2[10]; tmp1[11] ^= tmp2[11]; tmp1[12] ^= tmp2[12]; tmp1[13] ^= tmp2[13]; tmp1[14] ^= tmp2[14]; tmp1[15] ^= tmp2[15];
	memcpy(buf, tmp1, 64);
	return true;
}

bool s20_crypt128_2(uint8_t *key, uint32_t buf_sec, uint8_t *buf, uint32_t buflen) {
	uint8_t i;
	uint8_t keystemp[64];
	uint8_t n[] = {0, 0, 0, 0, 7, 2, 7, 2, 0, 0, 0, 0, 0, 0, 0, 0};
	memcpy(n + 8, &buf_sec, 4);
	s20_expand16(key, n, keystemp);
	for (i = 0; i < buflen; ++i) {
	    buf[i] ^= keystemp[i];
	}
	return true;
}

bool s20_crypt256_2(uint8_t *key, uint32_t buf_sec, uint8_t *buf, uint32_t buflen) {
	uint8_t i;
	uint8_t keystemp[64];
	uint8_t n[] = {0, 0, 0, 0, 7, 2, 7, 2, 0, 0, 0, 0, 0, 0, 0, 0};
	memcpy(n + 8, &buf_sec, 4);
	s20_expand32(key, n, keystemp);
	for (i = 0; i < buflen; ++i) {
	    buf[i] ^= keystemp[i];
	}
	return true;
}
	
void salsa20_128(const char *fileName, const char *key) {
	uint8_t temp[BN]; //40KByte memory
	int file = open(fileName, O_RDWR, S_IRUSR | S_IWUSR);

	int readSize = 0;
	int bufsec = 0;
	int i;
	while (readSize = read(file, temp, BN)) {
		
		if (readSize <= 0) break;

		for (i = 0; i < readSize; i += 64) {
			if (i + 64 <= readSize) s20_crypt128((uint8_t*)key, bufsec++, (uint8_t*)temp + i);
			else s20_crypt128_2((uint8_t*)key, bufsec++, (uint8_t*)temp + i, readSize - i);
		}

		lseek(file, -readSize, SEEK_CUR);
		write(file, temp, readSize);
		lseek(file, 0, SEEK_CUR);
	}
	close(file);
}

void salsa20_256(const char *fileName, const char *key) {
	uint8_t temp[BN]; //40KByte memory
	int file = open(fileName, O_RDWR | O_BINARY, S_IRWXU);

	fdatasync(file);
    posix_fadvise(file, 0,0,POSIX_FADV_DONTNEED);

	int readSize = 0;
	int bufsec = 0;
	int i;

	long long totalSize = 0;

	while (readSize = read(file, temp, BN)) {
		if (readSize < 0) break;
		for (i = 0; i < readSize; i += 64) {
			if (i + 64 <= readSize) s20_crypt256((uint8_t*)key, bufsec++, (uint8_t*)temp + i);
			else s20_crypt256_2((uint8_t*)key, bufsec++, (uint8_t*)temp + i, readSize - i);
		}
		lseek(file, -readSize, SEEK_CUR);
		write(file, temp, readSize);
		lseek(file, 0, SEEK_CUR);
		posix_fadvise(file, 0,0,POSIX_FADV_DONTNEED);
	}
    posix_fadvise(file, 0,0,POSIX_FADV_DONTNEED);
	close(file);
}

int main() {
	salsa20_256("encrytion_file.dat", "PASSWORDTYPE1___!@#$%^&*()!@#$%^");
	return 0;
}
