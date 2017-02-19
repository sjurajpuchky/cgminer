/*
 * bitshared.h
 *
 *  Created on: 12.2.2014
 *      Author: jpuchky
 */

#ifndef BITSHARED_H_
#define BITSHARED_H_
#include <stdbool.h>

typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

#define countSelector 4
extern uint32_t const m32_8[countSelector];
extern uint32_t const m_32_8[countSelector];
extern uint32_t const _m32_8[countSelector];
extern uint32_t const o32_8[countSelector];


//uint32_t const m32_8[countSelector] = { 0xFF, 0x00FF, 0x0000FF, 0x000000FF };
//uint32_t const m_32_8[countSelector] = { 0x000000FF, 0x0000FF00, 0x00FF0000, 0xFF000000 };
//uint32_t const _m32_8[countSelector] = { 0x00FFFFFF, 0xFF00FFFF, 0xFFFF00FF, 0xFFFFFF00 };
//uint32_t const o32_8[countSelector] = { 0, 8, 16, 24 };

#define selectSegment32_8M(nonce,i) ((unsigned char)(nonce > 0xFF ? \
									 (((nonce & m_32_8[i]) >> o32_8[i]) == 0 ? 0xFF : ((nonce & m_32_8[i]) >> o32_8[i])) \
									 : ((nonce & m_32_8[i]) >> o32_8[i]) \
									))
#define selectSegment32_8(nonce,i) ((unsigned char)(nonce & m_32_8[i]) >> o32_8[i])
#define combineSegment32_8(nonce,i,segment) ((uint32_t) (((uint32_t)(segment << o32_8[i]) & _m32_8[i]) | (uint32_t)nonce))
#define selectByte(nonce,i)    ((nonce & m_32_8[i]) >> o32_8[i])
#define prepareSegment(segment,i) ((uint32_t)((segment << o32_8[i]) << o32_8[i]))

#define REDUCE(x)        ({((x & m[0]) >> o[0]), \
						   ((x & m[1]) >> o[1]), \
						   ((x & m[2]) >> o[2]), \
						   ((x & m[3]) >> o[3])})

#define PRODUCE(a) (((a[0] & m[0]) << o[0]) | ((a[1] & m[0]) << o[1]) | ((a[2] & m[0]) << o[2]) | ((a[3] & m[0]) << o[3]))

#define SEMISOLVED(x)        (((x & m[0]) >> o[0])==0 | \
							  ((x & m[1]) >> o[1])==0 | \
							  ((x & m[2]) >> o[2])==0 | \
							  ((x & m[3]) >> o[3])==0)

#define SEMIASOLVED(x) ({((x & m[0]) >> o[0])==0, \
		                 ((x & m[1]) >> o[1])==0, \
		                 ((x & m[2]) >> o[2])==0, \
		                 ((x & m[3]) >> o[3])==0})

#define SEMIRESOLVED(x1,x2) {}

#define MAX_SEMI_RESULT_BUFF_SIZE 		4096
#define MAX_SEMI_RESULT_NS__BUFF_SIZE 	MAX_SEMI_RESULT_BUFF_SIZE*256

enum e_semiResultsStatus {
	SR_NONE, SR_SUCCESS, SR_FAIL, SR_FOUND
};

enum e_nonceLookupStatus {
	NL_INPROGRESS, NL_RESTART, NL_COMPLETE, NL_SUCCESS
};

typedef bool (*semiResultCallBack_func)();
typedef enum e_semiResultsStatus semiResultsStatus;
typedef enum e_nonceLookupStatus nonceLookupStatus;
typedef uint32_t u32;
typedef uint8_t u8;

typedef struct _semiResult {
	uint32_t nonce;
	semiResultsStatus status;
	unsigned char hash[32];
	unsigned char target[32];
} semiResult;

extern semiResult semiResultBuffer[MAX_SEMI_RESULT_BUFF_SIZE];
extern uint32_t semiResultNSBuffer[MAX_SEMI_RESULT_NS__BUFF_SIZE];
extern unsigned char *usedBlockMap;

extern const uint32_t lock_8[];
extern const uint32_t unlock_8[];

//uint32_t const lock_8[] = { 1, 2, 5, 8, 16, 32, 64, 128 };
//uint32_t const unlock_8[] = { 0b11111110, 0b11111101, 0b11111011, 0b11110111, 0b11101111, 0b11011111, 0b10111111, 0b01111111 };

#define lockNonce(n) {usedBlockMap[n / 8] = usedBlockMap[n / 8] | lock_8[n % 8];}
#define unlockNonce(n) {usedBlockMap[n / 8] = usedBlockMap[n / 8] & lock_8[n % 8];}
#define isNonceLocked(n) ((usedBlockMap[n / 8] & lock_8[n % 8]) > 0 ? true : false)
#define unlockAllNonces(max_nonce) { \
									 memset(usedBlockMap,0,max_nonce / 8); \
								   }

#define unreleaseAllNonces() { \
							   if(usedBlockMap!=NULL) { \
								 free(usedBlockMap); \
							   } \
							 }

extern void cleanUpSemiResults();
extern void onSemiResultsAreFull();
extern void addSemiResult(uint32_t *nonce, unsigned char *hash, const unsigned char *target, semiResultCallBack_func semiResultsAreFullCallBack);
extern void removeSemiResults();
extern void removeSemiResult(int r);

#endif /* BITSHARED_H_ */
