/*
*******************************************************************************
\file belt.c
\brief STB 34.101.31 (belt): data encryption and integrity algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2015.11.17
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/core/word.h"
#include "bee2/math/pp.h"
#include "bee2/math/ww.h"
#include "bee2/crypto/belt.h"

/*
*******************************************************************************
\todo Состояния некоторых связок (например, beltHash) содержат память, которую 
не обязательно поддерживать постоянной между обращениями к функциям связки. 
Это -- дополнительный управляемый стек. Можно передавать указатель на эту 
память через дополнительный параметр (stack, а не state), описав предварительно
глубину стека с помощью функций типа _deep. Мы не стали так делать, чтобы 
не усложнять излишне интерфейсы.
*******************************************************************************
*/

/*
*******************************************************************************
Ускорители

Реализованы быстрые операции над блоками и полублоками belt. Блок
представляется либо как [16]octet, либо как [4]u32,
либо как [W_OF_B(128)]word.

Суффикс U32 в именах макросов и функций означает, что данные интерпретируются
как массив u32. Суффикс W означает, что данные интерпретируются как
массив word.
*******************************************************************************
*/
#if (B_PER_W == 16)

#define beltBlockSetZero(block)\
	((word*)(block))[0] = 0,\
	((word*)(block))[1] = 0,\
	((word*)(block))[2] = 0,\
	((word*)(block))[3] = 0,\
	((word*)(block))[4] = 0,\
	((word*)(block))[5] = 0,\
	((word*)(block))[6] = 0,\
	((word*)(block))[7] = 0\

#define beltBlockRevW(block)\
	((word*)(block))[0] = wordRev(((word*)(block))[0]),\
	((word*)(block))[1] = wordRev(((word*)(block))[1]),\
	((word*)(block))[2] = wordRev(((word*)(block))[2]),\
	((word*)(block))[3] = wordRev(((word*)(block))[3]),\
	((word*)(block))[4] = wordRev(((word*)(block))[4]),\
	((word*)(block))[5] = wordRev(((word*)(block))[5]),\
	((word*)(block))[6] = wordRev(((word*)(block))[6]),\
	((word*)(block))[7] = wordRev(((word*)(block))[7])\

#define beltHalfBlockIsZero(block)\
	(((word*)(block))[0] == 0 && ((word*)(block))[1] == 0 &&\
		((word*)(block))[2] == 0 && ((word*)(block))[3] == 0)

#define beltBlockNeg(dest, src)\
	((word*)(dest))[0] = ~((const word*)(src))[0],\
	((word*)(dest))[1] = ~((const word*)(src))[1],\
	((word*)(dest))[2] = ~((const word*)(src))[2],\
	((word*)(dest))[3] = ~((const word*)(src))[3],\
	((word*)(dest))[4] = ~((const word*)(src))[4],\
	((word*)(dest))[5] = ~((const word*)(src))[5],\
	((word*)(dest))[6] = ~((const word*)(src))[6],\
	((word*)(dest))[7] = ~((const word*)(src))[7]\

#define beltBlockXor(dest, src1, src2)\
	((word*)(dest))[0] = ((const word*)(src1))[0] ^ ((const word*)(src2))[0],\
	((word*)(dest))[1] = ((const word*)(src1))[1] ^ ((const word*)(src2))[1],\
	((word*)(dest))[2] = ((const word*)(src1))[2] ^ ((const word*)(src2))[2],\
	((word*)(dest))[3] = ((const word*)(src1))[3] ^ ((const word*)(src2))[3],\
	((word*)(dest))[4] = ((const word*)(src1))[4] ^ ((const word*)(src2))[4],\
	((word*)(dest))[5] = ((const word*)(src1))[5] ^ ((const word*)(src2))[5],\
	((word*)(dest))[6] = ((const word*)(src1))[6] ^ ((const word*)(src2))[6],\
	((word*)(dest))[7] = ((const word*)(src1))[7] ^ ((const word*)(src2))[7]\

#define beltBlockXor2(dest, src)\
	((word*)(dest))[0] ^= ((const word*)(src))[0],\
	((word*)(dest))[1] ^= ((const word*)(src))[1],\
	((word*)(dest))[2] ^= ((const word*)(src))[2],\
	((word*)(dest))[3] ^= ((const word*)(src))[3],\
	((word*)(dest))[4] ^= ((const word*)(src))[4],\
	((word*)(dest))[5] ^= ((const word*)(src))[5],\
	((word*)(dest))[6] ^= ((const word*)(src))[6],\
	((word*)(dest))[7] ^= ((const word*)(src))[7]\

#define beltBlockCopy(dest, src)\
	((word*)(dest))[0] = ((const word*)(src))[0],\
	((word*)(dest))[1] = ((const word*)(src))[1],\
	((word*)(dest))[2] = ((const word*)(src))[2],\
	((word*)(dest))[3] = ((const word*)(src))[3],\
	((word*)(dest))[4] = ((const word*)(src))[4],\
	((word*)(dest))[5] = ((const word*)(src))[5],\
	((word*)(dest))[6] = ((const word*)(src))[6],\
	((word*)(dest))[7] = ((const word*)(src))[7]\

#elif (B_PER_W == 32)

#define beltBlockSetZero(block)\
	((word*)(block))[0] = 0,\
	((word*)(block))[1] = 0,\
	((word*)(block))[2] = 0,\
	((word*)(block))[3] = 0\

#define beltBlockRevW(block)\
	((word*)(block))[0] = wordRev(((word*)(block))[0]),\
	((word*)(block))[1] = wordRev(((word*)(block))[1]),\
	((word*)(block))[2] = wordRev(((word*)(block))[2]),\
	((word*)(block))[3] = wordRev(((word*)(block))[3])\

#define beltHalfBlockIsZero(block)\
	(((word*)(block))[0] == 0 && ((word*)(block))[1] == 0)\

#define beltBlockNeg(dest, src)\
	((word*)(dest))[0] = ~((const word*)(src))[0],\
	((word*)(dest))[1] = ~((const word*)(src))[1],\
	((word*)(dest))[2] = ~((const word*)(src))[2],\
	((word*)(dest))[3] = ~((const word*)(src))[3]\

#define beltBlockXor(dest, src1, src2)\
	((word*)(dest))[0] = ((const word*)(src1))[0] ^ ((const word*)(src2))[0],\
	((word*)(dest))[1] = ((const word*)(src1))[1] ^ ((const word*)(src2))[1],\
	((word*)(dest))[2] = ((const word*)(src1))[2] ^ ((const word*)(src2))[2],\
	((word*)(dest))[3] = ((const word*)(src1))[3] ^ ((const word*)(src2))[3]\

#define beltBlockXor2(dest, src)\
	((word*)(dest))[0] ^= ((const word*)(src))[0],\
	((word*)(dest))[1] ^= ((const word*)(src))[1],\
	((word*)(dest))[2] ^= ((const word*)(src))[2],\
	((word*)(dest))[3] ^= ((const word*)(src))[3]\

#define beltBlockCopy(dest, src)\
	((word*)(dest))[0] = ((const word*)(src))[0],\
	((word*)(dest))[1] = ((const word*)(src))[1],\
	((word*)(dest))[2] = ((const word*)(src))[2],\
	((word*)(dest))[3] = ((const word*)(src))[3]\

#elif (B_PER_W == 64)

#define beltBlockSetZero(block)\
	((word*)(block))[0] = 0,\
	((word*)(block))[1] = 0\

#define beltBlockRevW(block)\
	((word*)(block))[0] = wordRev(((word*)(block))[0]),\
	((word*)(block))[1] = wordRev(((word*)(block))[1])\

#define beltHalfBlockIsZero(block)\
	(((word*)(block))[0] == 0)\

#define beltBlockNeg(dest, src)\
	((word*)(dest))[0] = ~((const word*)(src))[0],\
	((word*)(dest))[1] = ~((const word*)(src))[1]\

#define beltBlockXor(dest, src1, src2)\
	((word*)(dest))[0] = ((const word*)(src1))[0] ^ ((const word*)(src2))[0],\
	((word*)(dest))[1] = ((const word*)(src1))[1] ^ ((const word*)(src2))[1];\

#define beltBlockXor2(dest, src)\
	((word*)(dest))[0] ^= ((const word*)(src))[0],\
	((word*)(dest))[1] ^= ((const word*)(src))[1]\

#define beltBlockCopy(dest, src)\
	((word*)(dest))[0] = ((const word*)(src))[0],\
	((word*)(dest))[1] = ((const word*)(src))[1]\

#else
	#error "Unsupported word size"
#endif // B_PER_W

#define beltBlockRevU32(block)\
	((u32*)(block))[0] = u32Rev(((u32*)(block))[0]),\
	((u32*)(block))[1] = u32Rev(((u32*)(block))[1]),\
	((u32*)(block))[2] = u32Rev(((u32*)(block))[2]),\
	((u32*)(block))[3] = u32Rev(((u32*)(block))[3])\

#define beltBlockIncU32(block)\
	if ((((u32*)(block))[0] += 1) == 0 &&\
		(((u32*)(block))[1] += 1) == 0 &&\
		(((u32*)(block))[2] += 1) == 0)\
		((u32*)(block))[3] += 1\

static void beltBlockAddBitSizeU32(u32 block[4], size_t count)
{
	// block <- block + 8 * count
	register u32 carry = (u32)count << 3;
#if (B_PER_S < 32)
	carry = (block[0] += carry) < carry;
	carry = (block[1] += carry) < carry;
	carry = (block[2] += carry) < carry;
	block[3] += carry;
#else
	register size_t t = count >> 29;
	carry = (block[0] += carry) < carry;
	if ((block[1] += carry) < carry)
		block[1] = (u32)t;
	else
		carry = (block[1] += (u32)t) < (u32)t;
	t >>= 16, t >>= 16;
	if ((block[2] += carry) < carry)
		block[2] = (u32)t;
	else
		carry = (block[2] += (u32)t) < (u32)t;
	t >>= 16, t >>= 16;
	block[3] += carry;
	block[3] += (u32)t;
	t = 0;
#endif
	carry = 0;
}

static void beltHalfBlockAddBitSizeW(word block[W_OF_B(64)], size_t count)
{
	// block <- block + 8 * count
	register word carry = (word)count << 3;
#if (B_PER_W == 16)
	register size_t t = count >> 13;
	carry = (block[0] += carry) < carry;
	if ((block[1] += carry) < carry)
		block[1] = (word)t;
	else
		carry = (block[1] += (word)t) < (word)t;
	t >>= 8, t >>= 8;
	if ((block[2] += carry) < carry)
		block[2] = (word)t;
	else
		carry = (block[2] += (word)t) < (word)t;
	t >>= 8, t >>= 8;
	block[3] += carry;
	block[3] += (word)t;
#elif (B_PER_W == 32)
	register size_t t = count;
	carry = (block[0] += carry) < carry;
	t >>= 15, t >>= 14;
	block[1] += carry;
	block[1] += (u32)t;
	t = 0;
#elif (B_PER_W == 64)
	block[0] += carry;
#else
	#error "Unsupported word size"
#endif // B_PER_W
	carry = 0;
}

/*
*******************************************************************************
H-блок
*******************************************************************************
*/
static const octet H[256] = {
	0xB1,0x94,0xBA,0xC8,0x0A,0x08,0xF5,0x3B,0x36,0x6D,0x00,0x8E,0x58,0x4A,0x5D,0xE4,
	0x85,0x04,0xFA,0x9D,0x1B,0xB6,0xC7,0xAC,0x25,0x2E,0x72,0xC2,0x02,0xFD,0xCE,0x0D,
	0x5B,0xE3,0xD6,0x12,0x17,0xB9,0x61,0x81,0xFE,0x67,0x86,0xAD,0x71,0x6B,0x89,0x0B,
	0x5C,0xB0,0xC0,0xFF,0x33,0xC3,0x56,0xB8,0x35,0xC4,0x05,0xAE,0xD8,0xE0,0x7F,0x99,
	0xE1,0x2B,0xDC,0x1A,0xE2,0x82,0x57,0xEC,0x70,0x3F,0xCC,0xF0,0x95,0xEE,0x8D,0xF1,
	0xC1,0xAB,0x76,0x38,0x9F,0xE6,0x78,0xCA,0xF7,0xC6,0xF8,0x60,0xD5,0xBB,0x9C,0x4F,
	0xF3,0x3C,0x65,0x7B,0x63,0x7C,0x30,0x6A,0xDD,0x4E,0xA7,0x79,0x9E,0xB2,0x3D,0x31,
	0x3E,0x98,0xB5,0x6E,0x27,0xD3,0xBC,0xCF,0x59,0x1E,0x18,0x1F,0x4C,0x5A,0xB7,0x93,
	0xE9,0xDE,0xE7,0x2C,0x8F,0x0C,0x0F,0xA6,0x2D,0xDB,0x49,0xF4,0x6F,0x73,0x96,0x47,
	0x06,0x07,0x53,0x16,0xED,0x24,0x7A,0x37,0x39,0xCB,0xA3,0x83,0x03,0xA9,0x8B,0xF6,
	0x92,0xBD,0x9B,0x1C,0xE5,0xD1,0x41,0x01,0x54,0x45,0xFB,0xC9,0x5E,0x4D,0x0E,0xF2,
	0x68,0x20,0x80,0xAA,0x22,0x7D,0x64,0x2F,0x26,0x87,0xF9,0x34,0x90,0x40,0x55,0x11,
	0xBE,0x32,0x97,0x13,0x43,0xFC,0x9A,0x48,0xA0,0x2A,0x88,0x5F,0x19,0x4B,0x09,0xA1,
	0x7E,0xCD,0xA4,0xD0,0x15,0x44,0xAF,0x8C,0xA5,0x84,0x50,0xBF,0x66,0xD2,0xE8,0x8A,
	0xA2,0xD7,0x46,0x52,0x42,0xA8,0xDF,0xB3,0x69,0x74,0xC5,0x51,0xEB,0x23,0x29,0x21,
	0xD4,0xEF,0xD9,0xB4,0x3A,0x62,0x28,0x75,0x91,0x14,0x10,0xEA,0x77,0x6C,0xDA,0x1D,
};

const octet* beltH()
{
	return H;
}

/*
*******************************************************************************
Расширение ключа
*******************************************************************************
*/

void beltKeyExpand(octet key[32], const octet theta[], size_t len)
{
	ASSERT(memIsValid(key, 32));
	ASSERT(len == 16 || len == 24 || len == 32);
	ASSERT(memIsValid(theta, len));
	memMove(key, theta, len);
	if (len == 16)
		memCopy(key + 16, key, 16);
	else if (len == 24)
	{
		u32* w = (u32*)key;
		w[6] = w[0] ^ w[1] ^ w[2];
		w[7] = w[3] ^ w[4] ^ w[5];
	}
}

void beltKeyExpand2(u32 key[8], const octet theta[], size_t len)
{
	ASSERT(memIsValid(key, 32));
	ASSERT(len == 16 || len == 24 || len == 32);
	ASSERT(memIsValid(theta, len));
	u32From(key, theta, len);
	if (len == 16)
	{
		key[4] = key[0];
		key[5] = key[1];
		key[6] = key[2];
		key[7] = key[3];
	}
	else if (len == 24)
	{
		key[6] = key[0] ^ key[1] ^ key[2];
		key[7] = key[3] ^ key[4] ^ key[5];
	}
}

/*
*******************************************************************************
Расширенные H-блоки

\remark Описание построено с помощью функции:
\code
	void beltExtendBoxes()
	{
		unsigned r, x;
		u32 y;
		for (r = 5; r < 32; r += 8)
		{
			printf("static const u32 H%u[256] = {", r);
			for (x = 0; x < 256; x++)
				y = H[x],
				y = y << r | y >> (32 - r),
				printf(x % 8 ? "0x%08X," : "\n\t0x%08X,", y);
			printf("\n};\n");
		}
	}
\endcode
*******************************************************************************
*/

static const u32 H5[256] = {
	0x00001620,0x00001280,0x00001740,0x00001900,0x00000140,0x00000100,0x00001EA0,0x00000760,
	0x000006C0,0x00000DA0,0x00000000,0x000011C0,0x00000B00,0x00000940,0x00000BA0,0x00001C80,
	0x000010A0,0x00000080,0x00001F40,0x000013A0,0x00000360,0x000016C0,0x000018E0,0x00001580,
	0x000004A0,0x000005C0,0x00000E40,0x00001840,0x00000040,0x00001FA0,0x000019C0,0x000001A0,
	0x00000B60,0x00001C60,0x00001AC0,0x00000240,0x000002E0,0x00001720,0x00000C20,0x00001020,
	0x00001FC0,0x00000CE0,0x000010C0,0x000015A0,0x00000E20,0x00000D60,0x00001120,0x00000160,
	0x00000B80,0x00001600,0x00001800,0x00001FE0,0x00000660,0x00001860,0x00000AC0,0x00001700,
	0x000006A0,0x00001880,0x000000A0,0x000015C0,0x00001B00,0x00001C00,0x00000FE0,0x00001320,
	0x00001C20,0x00000560,0x00001B80,0x00000340,0x00001C40,0x00001040,0x00000AE0,0x00001D80,
	0x00000E00,0x000007E0,0x00001980,0x00001E00,0x000012A0,0x00001DC0,0x000011A0,0x00001E20,
	0x00001820,0x00001560,0x00000EC0,0x00000700,0x000013E0,0x00001CC0,0x00000F00,0x00001940,
	0x00001EE0,0x000018C0,0x00001F00,0x00000C00,0x00001AA0,0x00001760,0x00001380,0x000009E0,
	0x00001E60,0x00000780,0x00000CA0,0x00000F60,0x00000C60,0x00000F80,0x00000600,0x00000D40,
	0x00001BA0,0x000009C0,0x000014E0,0x00000F20,0x000013C0,0x00001640,0x000007A0,0x00000620,
	0x000007C0,0x00001300,0x000016A0,0x00000DC0,0x000004E0,0x00001A60,0x00001780,0x000019E0,
	0x00000B20,0x000003C0,0x00000300,0x000003E0,0x00000980,0x00000B40,0x000016E0,0x00001260,
	0x00001D20,0x00001BC0,0x00001CE0,0x00000580,0x000011E0,0x00000180,0x000001E0,0x000014C0,
	0x000005A0,0x00001B60,0x00000920,0x00001E80,0x00000DE0,0x00000E60,0x000012C0,0x000008E0,
	0x000000C0,0x000000E0,0x00000A60,0x000002C0,0x00001DA0,0x00000480,0x00000F40,0x000006E0,
	0x00000720,0x00001960,0x00001460,0x00001060,0x00000060,0x00001520,0x00001160,0x00001EC0,
	0x00001240,0x000017A0,0x00001360,0x00000380,0x00001CA0,0x00001A20,0x00000820,0x00000020,
	0x00000A80,0x000008A0,0x00001F60,0x00001920,0x00000BC0,0x000009A0,0x000001C0,0x00001E40,
	0x00000D00,0x00000400,0x00001000,0x00001540,0x00000440,0x00000FA0,0x00000C80,0x000005E0,
	0x000004C0,0x000010E0,0x00001F20,0x00000680,0x00001200,0x00000800,0x00000AA0,0x00000220,
	0x000017C0,0x00000640,0x000012E0,0x00000260,0x00000860,0x00001F80,0x00001340,0x00000900,
	0x00001400,0x00000540,0x00001100,0x00000BE0,0x00000320,0x00000960,0x00000120,0x00001420,
	0x00000FC0,0x000019A0,0x00001480,0x00001A00,0x000002A0,0x00000880,0x000015E0,0x00001180,
	0x000014A0,0x00001080,0x00000A00,0x000017E0,0x00000CC0,0x00001A40,0x00001D00,0x00001140,
	0x00001440,0x00001AE0,0x000008C0,0x00000A40,0x00000840,0x00001500,0x00001BE0,0x00001660,
	0x00000D20,0x00000E80,0x000018A0,0x00000A20,0x00001D60,0x00000460,0x00000520,0x00000420,
	0x00001A80,0x00001DE0,0x00001B20,0x00001680,0x00000740,0x00000C40,0x00000500,0x00000EA0,
	0x00001220,0x00000280,0x00000200,0x00001D40,0x00000EE0,0x00000D80,0x00001B40,0x000003A0,
};
static const u32 H13[256] = {
	0x00162000,0x00128000,0x00174000,0x00190000,0x00014000,0x00010000,0x001EA000,0x00076000,
	0x0006C000,0x000DA000,0x00000000,0x0011C000,0x000B0000,0x00094000,0x000BA000,0x001C8000,
	0x0010A000,0x00008000,0x001F4000,0x0013A000,0x00036000,0x0016C000,0x0018E000,0x00158000,
	0x0004A000,0x0005C000,0x000E4000,0x00184000,0x00004000,0x001FA000,0x0019C000,0x0001A000,
	0x000B6000,0x001C6000,0x001AC000,0x00024000,0x0002E000,0x00172000,0x000C2000,0x00102000,
	0x001FC000,0x000CE000,0x0010C000,0x0015A000,0x000E2000,0x000D6000,0x00112000,0x00016000,
	0x000B8000,0x00160000,0x00180000,0x001FE000,0x00066000,0x00186000,0x000AC000,0x00170000,
	0x0006A000,0x00188000,0x0000A000,0x0015C000,0x001B0000,0x001C0000,0x000FE000,0x00132000,
	0x001C2000,0x00056000,0x001B8000,0x00034000,0x001C4000,0x00104000,0x000AE000,0x001D8000,
	0x000E0000,0x0007E000,0x00198000,0x001E0000,0x0012A000,0x001DC000,0x0011A000,0x001E2000,
	0x00182000,0x00156000,0x000EC000,0x00070000,0x0013E000,0x001CC000,0x000F0000,0x00194000,
	0x001EE000,0x0018C000,0x001F0000,0x000C0000,0x001AA000,0x00176000,0x00138000,0x0009E000,
	0x001E6000,0x00078000,0x000CA000,0x000F6000,0x000C6000,0x000F8000,0x00060000,0x000D4000,
	0x001BA000,0x0009C000,0x0014E000,0x000F2000,0x0013C000,0x00164000,0x0007A000,0x00062000,
	0x0007C000,0x00130000,0x0016A000,0x000DC000,0x0004E000,0x001A6000,0x00178000,0x0019E000,
	0x000B2000,0x0003C000,0x00030000,0x0003E000,0x00098000,0x000B4000,0x0016E000,0x00126000,
	0x001D2000,0x001BC000,0x001CE000,0x00058000,0x0011E000,0x00018000,0x0001E000,0x0014C000,
	0x0005A000,0x001B6000,0x00092000,0x001E8000,0x000DE000,0x000E6000,0x0012C000,0x0008E000,
	0x0000C000,0x0000E000,0x000A6000,0x0002C000,0x001DA000,0x00048000,0x000F4000,0x0006E000,
	0x00072000,0x00196000,0x00146000,0x00106000,0x00006000,0x00152000,0x00116000,0x001EC000,
	0x00124000,0x0017A000,0x00136000,0x00038000,0x001CA000,0x001A2000,0x00082000,0x00002000,
	0x000A8000,0x0008A000,0x001F6000,0x00192000,0x000BC000,0x0009A000,0x0001C000,0x001E4000,
	0x000D0000,0x00040000,0x00100000,0x00154000,0x00044000,0x000FA000,0x000C8000,0x0005E000,
	0x0004C000,0x0010E000,0x001F2000,0x00068000,0x00120000,0x00080000,0x000AA000,0x00022000,
	0x0017C000,0x00064000,0x0012E000,0x00026000,0x00086000,0x001F8000,0x00134000,0x00090000,
	0x00140000,0x00054000,0x00110000,0x000BE000,0x00032000,0x00096000,0x00012000,0x00142000,
	0x000FC000,0x0019A000,0x00148000,0x001A0000,0x0002A000,0x00088000,0x0015E000,0x00118000,
	0x0014A000,0x00108000,0x000A0000,0x0017E000,0x000CC000,0x001A4000,0x001D0000,0x00114000,
	0x00144000,0x001AE000,0x0008C000,0x000A4000,0x00084000,0x00150000,0x001BE000,0x00166000,
	0x000D2000,0x000E8000,0x0018A000,0x000A2000,0x001D6000,0x00046000,0x00052000,0x00042000,
	0x001A8000,0x001DE000,0x001B2000,0x00168000,0x00074000,0x000C4000,0x00050000,0x000EA000,
	0x00122000,0x00028000,0x00020000,0x001D4000,0x000EE000,0x000D8000,0x001B4000,0x0003A000,
};
static const u32 H21[256] = {
	0x16200000,0x12800000,0x17400000,0x19000000,0x01400000,0x01000000,0x1EA00000,0x07600000,
	0x06C00000,0x0DA00000,0x00000000,0x11C00000,0x0B000000,0x09400000,0x0BA00000,0x1C800000,
	0x10A00000,0x00800000,0x1F400000,0x13A00000,0x03600000,0x16C00000,0x18E00000,0x15800000,
	0x04A00000,0x05C00000,0x0E400000,0x18400000,0x00400000,0x1FA00000,0x19C00000,0x01A00000,
	0x0B600000,0x1C600000,0x1AC00000,0x02400000,0x02E00000,0x17200000,0x0C200000,0x10200000,
	0x1FC00000,0x0CE00000,0x10C00000,0x15A00000,0x0E200000,0x0D600000,0x11200000,0x01600000,
	0x0B800000,0x16000000,0x18000000,0x1FE00000,0x06600000,0x18600000,0x0AC00000,0x17000000,
	0x06A00000,0x18800000,0x00A00000,0x15C00000,0x1B000000,0x1C000000,0x0FE00000,0x13200000,
	0x1C200000,0x05600000,0x1B800000,0x03400000,0x1C400000,0x10400000,0x0AE00000,0x1D800000,
	0x0E000000,0x07E00000,0x19800000,0x1E000000,0x12A00000,0x1DC00000,0x11A00000,0x1E200000,
	0x18200000,0x15600000,0x0EC00000,0x07000000,0x13E00000,0x1CC00000,0x0F000000,0x19400000,
	0x1EE00000,0x18C00000,0x1F000000,0x0C000000,0x1AA00000,0x17600000,0x13800000,0x09E00000,
	0x1E600000,0x07800000,0x0CA00000,0x0F600000,0x0C600000,0x0F800000,0x06000000,0x0D400000,
	0x1BA00000,0x09C00000,0x14E00000,0x0F200000,0x13C00000,0x16400000,0x07A00000,0x06200000,
	0x07C00000,0x13000000,0x16A00000,0x0DC00000,0x04E00000,0x1A600000,0x17800000,0x19E00000,
	0x0B200000,0x03C00000,0x03000000,0x03E00000,0x09800000,0x0B400000,0x16E00000,0x12600000,
	0x1D200000,0x1BC00000,0x1CE00000,0x05800000,0x11E00000,0x01800000,0x01E00000,0x14C00000,
	0x05A00000,0x1B600000,0x09200000,0x1E800000,0x0DE00000,0x0E600000,0x12C00000,0x08E00000,
	0x00C00000,0x00E00000,0x0A600000,0x02C00000,0x1DA00000,0x04800000,0x0F400000,0x06E00000,
	0x07200000,0x19600000,0x14600000,0x10600000,0x00600000,0x15200000,0x11600000,0x1EC00000,
	0x12400000,0x17A00000,0x13600000,0x03800000,0x1CA00000,0x1A200000,0x08200000,0x00200000,
	0x0A800000,0x08A00000,0x1F600000,0x19200000,0x0BC00000,0x09A00000,0x01C00000,0x1E400000,
	0x0D000000,0x04000000,0x10000000,0x15400000,0x04400000,0x0FA00000,0x0C800000,0x05E00000,
	0x04C00000,0x10E00000,0x1F200000,0x06800000,0x12000000,0x08000000,0x0AA00000,0x02200000,
	0x17C00000,0x06400000,0x12E00000,0x02600000,0x08600000,0x1F800000,0x13400000,0x09000000,
	0x14000000,0x05400000,0x11000000,0x0BE00000,0x03200000,0x09600000,0x01200000,0x14200000,
	0x0FC00000,0x19A00000,0x14800000,0x1A000000,0x02A00000,0x08800000,0x15E00000,0x11800000,
	0x14A00000,0x10800000,0x0A000000,0x17E00000,0x0CC00000,0x1A400000,0x1D000000,0x11400000,
	0x14400000,0x1AE00000,0x08C00000,0x0A400000,0x08400000,0x15000000,0x1BE00000,0x16600000,
	0x0D200000,0x0E800000,0x18A00000,0x0A200000,0x1D600000,0x04600000,0x05200000,0x04200000,
	0x1A800000,0x1DE00000,0x1B200000,0x16800000,0x07400000,0x0C400000,0x05000000,0x0EA00000,
	0x12200000,0x02800000,0x02000000,0x1D400000,0x0EE00000,0x0D800000,0x1B400000,0x03A00000,
};
static const u32 H29[256] = {
	0x20000016,0x80000012,0x40000017,0x00000019,0x40000001,0x00000001,0xA000001E,0x60000007,
	0xC0000006,0xA000000D,0x00000000,0xC0000011,0x0000000B,0x40000009,0xA000000B,0x8000001C,
	0xA0000010,0x80000000,0x4000001F,0xA0000013,0x60000003,0xC0000016,0xE0000018,0x80000015,
	0xA0000004,0xC0000005,0x4000000E,0x40000018,0x40000000,0xA000001F,0xC0000019,0xA0000001,
	0x6000000B,0x6000001C,0xC000001A,0x40000002,0xE0000002,0x20000017,0x2000000C,0x20000010,
	0xC000001F,0xE000000C,0xC0000010,0xA0000015,0x2000000E,0x6000000D,0x20000011,0x60000001,
	0x8000000B,0x00000016,0x00000018,0xE000001F,0x60000006,0x60000018,0xC000000A,0x00000017,
	0xA0000006,0x80000018,0xA0000000,0xC0000015,0x0000001B,0x0000001C,0xE000000F,0x20000013,
	0x2000001C,0x60000005,0x8000001B,0x40000003,0x4000001C,0x40000010,0xE000000A,0x8000001D,
	0x0000000E,0xE0000007,0x80000019,0x0000001E,0xA0000012,0xC000001D,0xA0000011,0x2000001E,
	0x20000018,0x60000015,0xC000000E,0x00000007,0xE0000013,0xC000001C,0x0000000F,0x40000019,
	0xE000001E,0xC0000018,0x0000001F,0x0000000C,0xA000001A,0x60000017,0x80000013,0xE0000009,
	0x6000001E,0x80000007,0xA000000C,0x6000000F,0x6000000C,0x8000000F,0x00000006,0x4000000D,
	0xA000001B,0xC0000009,0xE0000014,0x2000000F,0xC0000013,0x40000016,0xA0000007,0x20000006,
	0xC0000007,0x00000013,0xA0000016,0xC000000D,0xE0000004,0x6000001A,0x80000017,0xE0000019,
	0x2000000B,0xC0000003,0x00000003,0xE0000003,0x80000009,0x4000000B,0xE0000016,0x60000012,
	0x2000001D,0xC000001B,0xE000001C,0x80000005,0xE0000011,0x80000001,0xE0000001,0xC0000014,
	0xA0000005,0x6000001B,0x20000009,0x8000001E,0xE000000D,0x6000000E,0xC0000012,0xE0000008,
	0xC0000000,0xE0000000,0x6000000A,0xC0000002,0xA000001D,0x80000004,0x4000000F,0xE0000006,
	0x20000007,0x60000019,0x60000014,0x60000010,0x60000000,0x20000015,0x60000011,0xC000001E,
	0x40000012,0xA0000017,0x60000013,0x80000003,0xA000001C,0x2000001A,0x20000008,0x20000000,
	0x8000000A,0xA0000008,0x6000001F,0x20000019,0xC000000B,0xA0000009,0xC0000001,0x4000001E,
	0x0000000D,0x00000004,0x00000010,0x40000015,0x40000004,0xA000000F,0x8000000C,0xE0000005,
	0xC0000004,0xE0000010,0x2000001F,0x80000006,0x00000012,0x00000008,0xA000000A,0x20000002,
	0xC0000017,0x40000006,0xE0000012,0x60000002,0x60000008,0x8000001F,0x40000013,0x00000009,
	0x00000014,0x40000005,0x00000011,0xE000000B,0x20000003,0x60000009,0x20000001,0x20000014,
	0xC000000F,0xA0000019,0x80000014,0x0000001A,0xA0000002,0x80000008,0xE0000015,0x80000011,
	0xA0000014,0x80000010,0x0000000A,0xE0000017,0xC000000C,0x4000001A,0x0000001D,0x40000011,
	0x40000014,0xE000001A,0xC0000008,0x4000000A,0x40000008,0x00000015,0xE000001B,0x60000016,
	0x2000000D,0x8000000E,0xA0000018,0x2000000A,0x6000001D,0x60000004,0x20000005,0x20000004,
	0x8000001A,0xE000001D,0x2000001B,0x80000016,0x40000007,0x4000000C,0x00000005,0xA000000E,
	0x20000012,0x80000002,0x00000002,0x4000001D,0xE000000E,0x8000000D,0x4000001B,0xA0000003,
};

/*
*******************************************************************************
G-блоки
*******************************************************************************
*/
#define G5(x)\
	H5[(x) & 255] ^ H13[(x) >> 8 & 255] ^ H21[(x) >> 16 & 255] ^ H29[(x) >> 24]
#define G13(x)\
	H13[(x) & 255] ^ H21[(x) >> 8 & 255] ^ H29[(x) >> 16 & 255] ^ H5[(x) >> 24]
#define G21(x)\
	H21[(x) & 255] ^ H29[(x) >> 8 & 255] ^ H5[(x) >> 16 & 255] ^ H13[(x) >> 24]

/*
*******************************************************************************
Тактовая подстановка

Макрос R реализует шаги 2.1-2.9 алгоритмов зашифрования и расшифрования.

На шагах 2.4-2.6 дополнительный регистр е не используется.
Нужные данные сохраняются в регистрах b и c.

Параметр-макрос subkey задает порядок использования тактовых ключей:
порядок subkey = subkey_e используется при зашифровании,
порядок subkey = subkey_d -- при расшифровании.
*******************************************************************************
*/
#define R(a, b, c, d, K, i, subkey)\
	*b ^= G5(*a + subkey(K, i, 0));\
	*c ^= G21(*d + subkey(K, i, 1));\
	*a -= G13(*b + subkey(K, i, 2));\
	*c += *b;\
	*b += G21(*c + subkey(K, i, 3)) ^ i;\
	*c -= *b;\
	*d += G13(*c + subkey(K, i, 4));\
	*b ^= G21(*a + subkey(K, i, 5));\
	*c ^= G5(*d + subkey(K, i, 6));\

#define subkey_e(K, i, j) K[(7 * i - 7 + j) % 8]
#define subkey_d(K, i, j) K[(7 * i - 1 - j) % 8]

/*
*******************************************************************************
Такты зашифрования

Перестановка содержимого регистров a, b, c, d реализуется перестановкой
параметров макроса R. После выполнения последнего макроса R и шагов 2.10-2.12
алгоритма зашифрования в регистрах a, b, c, d будут находиться значения,
соответствующие спецификации belt.

Окончательная перестановка abcd -> bdac реализуется инверсиями:
a <-> b, c <-> d, b <-> c.
*******************************************************************************
*/
#define E(a, b, c, d, K)\
	R(a, b, c, d, K, 1, subkey_e);\
	R(b, d, a, c, K, 2, subkey_e);\
	R(d, c, b, a, K, 3, subkey_e);\
	R(c, a, d, b, K, 4, subkey_e);\
	R(a, b, c, d, K, 5, subkey_e);\
	R(b, d, a, c, K, 6, subkey_e);\
	R(d, c, b, a, K, 7, subkey_e);\
	R(c, a, d, b, K, 8, subkey_e);\
	*a ^= *b, *b ^= *a, *a ^= *b;\
	*c ^= *d, *d ^= *c, *c ^= *d;\
	*b ^= *c, *c ^= *b, *b ^= *c;\

/*
*******************************************************************************
Такты расшифрования

Перестановка содержимого регистров a, b, c, d реализуется перестановкой
параметров макроса R. После выполнения последнего макроса R и шагов 2.10-2.12
алгоритма расшифрования в регистрах a, b, c, d будут находиться значения,
соответствующие спецификации belt.

Окончательная перестановка abcd -> cadb реализуется инверсиями:
a <-> b, c <-> d, a <-> d.
*******************************************************************************
*/
#define D(a, b, c, d, K)\
	R(a, b, c, d, K, 8, subkey_d);\
	R(c, a, d, b, K, 7, subkey_d);\
	R(d, c, b, a, K, 6, subkey_d);\
	R(b, d, a, c, K, 5, subkey_d);\
	R(a, b, c, d, K, 4, subkey_d);\
	R(c, a, d, b, K, 3, subkey_d);\
	R(d, c, b, a, K, 2, subkey_d);\
	R(b, d, a, c, K, 1, subkey_d);\
	*a ^= *b, *b ^= *a, *a ^= *b;\
	*c ^= *d, *d ^= *c, *c ^= *d;\
	*a ^= *d, *d ^= *a, *a ^= *d;\

/*
*******************************************************************************
Зашифрование блока
*******************************************************************************
*/
void beltBlockEncr(octet block[16], const u32 key[8])
{
	u32* t = (u32*)block;
	ASSERT(memIsDisjoint2(block, 16, key, 32));
#if (OCTET_ORDER == BIG_ENDIAN)
	t[0] = u32Rev(t[0]);
	t[1] = u32Rev(t[1]);
	t[2] = u32Rev(t[2]);
	t[3] = u32Rev(t[3]);
#endif
	E((t + 0), (t + 1), (t + 2), (t + 3), key);
#if (OCTET_ORDER == BIG_ENDIAN)
	t[3] = u32Rev(t[3]);
	t[2] = u32Rev(t[2]);
	t[1] = u32Rev(t[1]);
	t[0] = u32Rev(t[0]);
#endif
}

void beltBlockEncr2(u32 block[4], const u32 key[8])
{
	E((block + 0), (block + 1), (block + 2), (block + 3), key);
}
/*
*******************************************************************************
Расшифрование блока
*******************************************************************************
*/
void beltBlockDecr(octet block[16], const u32 key[8])
{
	u32* t = (u32*)block;
	ASSERT(memIsDisjoint2(block, 16, key, 32));
#if (OCTET_ORDER == BIG_ENDIAN)
	t[0] = u32Rev(t[0]);
	t[1] = u32Rev(t[1]);
	t[2] = u32Rev(t[2]);
	t[3] = u32Rev(t[3]);
#endif
	D((t + 0), (t + 1), (t + 2), (t + 3), key);
#if (OCTET_ORDER == BIG_ENDIAN)
	t[3] = u32Rev(t[3]);
	t[2] = u32Rev(t[2]);
	t[1] = u32Rev(t[1]);
	t[0] = u32Rev(t[0]);
#endif
}

void beltBlockDecr2(u32 block[4], const u32 key[8])
{
	D((block + 0), (block + 1), (block + 2), (block + 3), key);
}

/*
*******************************************************************************
Шифрование в режиме ECB
*******************************************************************************
*/
typedef struct
{
	u32 key[8];		/*< форматированный ключ */
} belt_ecb_st;

size_t beltECB_keep()
{
	return sizeof(belt_ecb_st);
}

void beltECBStart(void* state, const octet theta[], size_t len)
{
	belt_ecb_st* s = (belt_ecb_st*)state;
	ASSERT(memIsValid(s, beltECB_keep()));
	beltKeyExpand2(s->key, theta, len);
}

void beltECBStepE(void* buf, size_t count, void* state)
{
	belt_ecb_st* s = (belt_ecb_st*)state;
	ASSERT(count >= 16);
	ASSERT(memIsDisjoint2(buf, count, s, beltECB_keep()));
	// цикл по полным блокам
	while(count >= 16)
	{
		beltBlockEncr(buf, s->key);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок? кража блока
	if (count)
	{
		memSwap((octet*)buf - 16, buf, count);
		beltBlockEncr((octet*)buf - 16, s->key);
	}
}

void beltECBStepD(void* buf, size_t count, void* state)
{
	belt_ecb_st* s = (belt_ecb_st*)state;
	ASSERT(count >= 16);
	ASSERT(memIsDisjoint2(buf, count, s, beltECB_keep()));
	// цикл по полным блокам
	while(count >= 16)
	{
		beltBlockDecr(buf, s->key);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок? кража блока
	if (count)
	{
		memSwap((octet*)buf - 16, buf, count);
		beltBlockDecr((octet*)buf - 16, s->key);
	}
}

err_t beltECBEncr(void* dest, const void* src, size_t count,
	const octet theta[], size_t len)
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(theta, len) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltECB_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// зашифровать
	beltECBStart(state, theta, len);
	memMove(dest, src, count);
	beltECBStepE(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltECBDecr(void* dest, const void* src, size_t count,
	const octet theta[], size_t len)
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(theta, len) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltECB_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// расшифровать
	beltECBStart(state, theta, len);
	memMove(dest, src, count);
	beltECBStepD(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Шифрование в режиме CBС
*******************************************************************************
*/
typedef struct
{
	u32 key[8];		/*< форматированный ключ */
	octet block[16];	/*< вспомогательный блок */
	octet block2[16];	/*< еще один вспомогательный блок */
} belt_cbc_st;

size_t beltCBC_keep()
{
	return sizeof(belt_cbc_st);
}

void beltCBCStart(void* state, const octet theta[], size_t len, 
	const octet iv[16])
{
	belt_cbc_st* s = (belt_cbc_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltCBC_keep()));
	beltKeyExpand2(s->key, theta, len);
	beltBlockCopy(s->block, iv);
}

void beltCBCStepE(void* buf, size_t count, void* state)
{
	belt_cbc_st* s = (belt_cbc_st*)state;
	ASSERT(count >= 16);
	ASSERT(memIsDisjoint2(buf, count, state, beltCBC_keep()));
	// цикл по полным блокам
	while(count >= 16)
	{
		beltBlockXor2(s->block, buf);
		beltBlockEncr(s->block, s->key);
		beltBlockCopy(buf, s->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок? кража блока
	if (count)
	{
		memSwap((octet*)buf - 16, buf, count);
		memXor2((octet*)buf - 16, s->block, count);
		beltBlockEncr((octet*)buf - 16, s->key);
	}
}

void beltCBCStepD(void* buf, size_t count, void* state)
{
	belt_cbc_st* s = (belt_cbc_st*)state;
	ASSERT(count >= 16);
	ASSERT(memIsDisjoint2(buf, count, state, beltCBC_keep()));
	// цикл по полным блокам
	while(count >= 32 || count == 16)
	{
		beltBlockCopy(s->block2, buf);
		beltBlockDecr(buf, s->key);
		beltBlockXor2(buf, s->block);
		beltBlockCopy(s->block, s->block2);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок? кража блока
	if (count)
	{
		ASSERT(16 < count && count < 32);
		beltBlockDecr(buf, s->key);
		memSwap(buf, (octet*)buf + 16, count - 16);
		memXor2((octet*)buf + 16, buf, count - 16);
		beltBlockDecr(buf, s->key);
		beltBlockXor2(buf, s->block);
	}
}

err_t beltCBCEncr(void* dest, const void* src, size_t count,
	const octet theta[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(theta, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltCBC_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// зашифровать
	beltCBCStart(state, theta, len, iv);
	memMove(dest, src, count);
	beltCBCStepE(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltCBCDecr(void* dest, const void* src, size_t count,
	const octet theta[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(theta, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltCBC_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// расшифровать
	beltCBCStart(state, theta, len, iv);
	memMove(dest, src, count);
	beltCBCStepD(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Шифрование в режиме CFB
*******************************************************************************
*/
typedef struct
{
	u32 key[8];		/*< форматированный ключ */
	octet block[16];	/*< блок гаммы */
	size_t reserved;	/*< резерв октетов гаммы */
} belt_cfb_st;

size_t beltCFB_keep()
{
	return sizeof(belt_cfb_st);
}

void beltCFBStart(void* state, const octet theta[], size_t len, 
	const octet iv[16])
{
	belt_cfb_st* s = (belt_cfb_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltCFB_keep()));
	beltKeyExpand2(s->key, theta, len);
	beltBlockCopy(s->block, iv);
	s->reserved = 0;
}

void beltCFBStepE(void* buf, size_t count, void* state)
{
	belt_cfb_st* s = (belt_cfb_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCFB_keep()));
	// есть резерв гаммы?
	if (s->reserved)
	{
		if (s->reserved >= count)
		{
			memXor2(s->block + 16 - s->reserved, buf, count);
			memCopy(buf, s->block + 16 - s->reserved, count);
			s->reserved -= count;
			return;
		}
		memXor2(s->block + 16 - s->reserved, buf, s->reserved);
		memCopy(buf, s->block + 16 - s->reserved, s->reserved);
		count -= s->reserved;
		buf = (octet*)buf + s->reserved;
		s->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockEncr(s->block, s->key);
		beltBlockXor2(s->block, buf);
		beltBlockCopy(buf, s->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
		beltBlockEncr(s->block, s->key);
		memXor2(s->block, buf, count);
		memCopy(buf, s->block, count);
		s->reserved = 16 - count;
	}
}

void beltCFBStepD(void* buf, size_t count, void* state)
{
	belt_cfb_st* s = (belt_cfb_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCFB_keep()));
	// есть резерв гаммы?
	if (s->reserved)
	{
		if (s->reserved >= count)
		{
			memXor2(buf, s->block + 16 - s->reserved, count);
			memXor2(s->block + 16 - s->reserved, buf, count);
			s->reserved -= count;
			return;
		}
		memXor2(buf, s->block + 16 - s->reserved, s->reserved);
		memXor2(s->block + 16 - s->reserved, buf, s->reserved);
		count -= s->reserved;
		buf = (octet*)buf + s->reserved;
		s->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockEncr(s->block, s->key);
		beltBlockXor2(buf, s->block);
		beltBlockXor2(s->block, buf);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
		beltBlockEncr(s->block, s->key);
		memXor2(buf, s->block, count);
		memXor2(s->block, buf, count);
		s->reserved = 16 - count;
	}
}

err_t beltCFBEncr(void* dest, const void* src, size_t count,
	const octet theta[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(theta, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltCFB_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// зашифровать
	beltCFBStart(state, theta, len, iv);
	memMove(dest, src, count);
	beltCFBStepE(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltCFBDecr(void* dest, const void* src, size_t count,
	const octet theta[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(dest, count) ||
		!memIsValid(theta, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltCFB_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// расшифровать
	beltCFBStart(state, theta, len, iv);
	memMove(dest, src, count);
	beltCFBStepD(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Шифрование в режиме CTR

Для ускорения работы счетчик ctr хранится в виде [4]u32. Это позволяет
зашифровывать счетчик с помощью функции beltBlockEncr2(), в которой
не используется реверс октетов  даже на платформах BIG_ENDIAN.
Реверс применяется только перед использованием зашифрованного счетчика
в качестве гаммы.
*******************************************************************************
*/
typedef struct
{
	u32 key[8];		/*< форматированный ключ */
	u32 ctr[4];		/*< счетчик */
	octet block[16];	/*< блок гаммы */
	size_t reserved;	/*< резерв октетов гаммы */
} belt_ctr_st;

size_t beltCTR_keep()
{
	return sizeof(belt_ctr_st);
}

void beltCTRStart(void* state, const octet theta[], size_t len, 
	const octet iv[16])
{
	belt_ctr_st* s = (belt_ctr_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltCTR_keep()));
	beltKeyExpand2(s->key, theta, len);
	u32From(s->ctr, iv, 16);
	beltBlockEncr2(s->ctr, s->key);
	s->reserved = 0;
}

void beltCTRStepE(void* buf, size_t count, void* state)
{
	belt_ctr_st* s = (belt_ctr_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltCTR_keep()));
	// есть резерв гаммы?
	if (s->reserved)
	{
		if (s->reserved >= count)
		{
			memXor2(buf, s->block + 16 - s->reserved, count);
			s->reserved -= count;
			return;
		}
		memXor2(buf, s->block + 16 - s->reserved, s->reserved);
		count -= s->reserved;
		buf = (octet*)buf + s->reserved;
		s->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockIncU32(s->ctr);
		beltBlockCopy(s->block, s->ctr);
		beltBlockEncr2((u32*)s->block, s->key);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		beltBlockXor2(buf, s->block);
		buf = (octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
		beltBlockIncU32(s->ctr);
		beltBlockCopy(s->block, s->ctr);
		beltBlockEncr2((u32*)s->block, s->key);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		memXor2(buf, s->block, count);
		s->reserved = 16 - count;
	}
}

err_t beltCTR(void* dest, const void* src, size_t count,
	const octet theta[], size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(theta, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltCTR_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// зашифровать
	beltCTRStart(state, theta, len, iv);
	memMove(dest, src, count);
	beltCTRStepE(dest, count, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Имитозащита (MAC)

Для ускорения работы текущая имитовставка s хранится в виде [4]u32.
Это позволяет зашифровывать s с помощью функции beltBlockEncr2(),
в которой не используется реверс октетов даже на платформах BIG_ENDIAN.
Реверс применяется только перед сложением накопленного блока данных
с текущей имитовставкой.
*******************************************************************************
*/
typedef struct
{
	u32 key[8];		/*< форматированный ключ */
	u32 s[4];		/*< переменная s */
	u32 r[4];		/*< переменная r */
	u32 mac[4];		/*< окончательная имитовставка */
	octet block[16];	/*< блок данных */
	size_t filled;		/*< накоплено октетов в блоке */
} belt_mac_st;

size_t beltMAC_keep()
{
	return sizeof(belt_mac_st);
}

void beltMACStart(void* state, const octet theta[], size_t len)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(memIsValid(state, beltMAC_keep()));
	beltKeyExpand2(s->key, theta, len);
	beltBlockSetZero(s->s);
	beltBlockSetZero(s->r);
	beltBlockEncr2(s->r, s->key);
	s->filled = 0;
}

void beltMACStepA(const void* buf, size_t count, void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltMAC_keep()));
	// накопить полный блок
	if (s->filled < 16)
	{
		if (count <= 16 - s->filled)
		{
			memCopy(s->block + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memCopy(s->block + s->filled, buf, 16 - s->filled);
		count -= 16 - s->filled;
		buf = (const octet*)buf + 16 - s->filled;
		s->filled = 16;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		beltBlockXor2(s->s, s->block);
		beltBlockEncr2(s->s, s->key);
		beltBlockCopy(s->block, buf);
		buf = (const octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
	{
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		beltBlockXor2(s->s, s->block);
		beltBlockEncr2(s->s, s->key);
		memCopy(s->block, buf, count);
		s->filled = count;
	}
}

static void beltMACStepG_internal(void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(memIsValid(state, beltMAC_keep()));
	// полный блок?
	if (s->filled == 16)
	{
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		beltBlockXor(s->mac, s->s, s->block);
		s->mac[0] ^= s->r[1];
		s->mac[1] ^= s->r[2];
		s->mac[2] ^= s->r[3];
		s->mac[3] ^= s->r[0] ^ s->r[1];
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
	}
	// неполный (в т.ч. пустой) блок?
	else
	{
		s->block[s->filled] = 0x80;
		memSetZero(s->block + s->filled + 1, 16 - s->filled - 1);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
		beltBlockXor(s->mac, s->s, s->block);
		s->mac[0] ^= s->r[0] ^ s->r[3];
		s->mac[1] ^= s->r[0];
		s->mac[2] ^= s->r[1];
		s->mac[3] ^= s->r[2];
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
#endif
	}
	beltBlockEncr2(s->mac, s->key);
}

void beltMACStepG(octet mac[8], void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltMACStepG_internal(s);
	u32To(mac, 8, s->mac);
}

void beltMACStepG2(octet mac[], size_t mac_len, void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(mac_len <= 8);
	ASSERT(memIsValid(mac, mac_len));
	beltMACStepG_internal(s);
	u32To(mac, mac_len, s->mac);
}

bool_t beltMACStepV(const octet mac[8], void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltMACStepG_internal(s);
#if (OCTET_ORDER == BIG_ENDIAN)
	s->mac[0] = u32Rev(s->mac[0]);
	s->mac[1] = u32Rev(s->mac[1]);
#endif
	return memEq(mac, s->mac, 8);
}

bool_t beltMACStepV2(const octet mac[], size_t mac_len, void* state)
{
	belt_mac_st* s = (belt_mac_st*)state;
	ASSERT(mac_len <= 8);
	ASSERT(memIsValid(mac, mac_len));
	beltMACStepG_internal(s);
#if (OCTET_ORDER == BIG_ENDIAN)
	s->mac[0] = u32Rev(s->mac[0]);
	s->mac[1] = u32Rev(s->mac[1]);
#endif
	return memEq(mac, s->mac, mac_len);
}

err_t beltMAC(octet mac[8], const void* src, size_t count,
	const octet theta[], size_t len)
{
	void* state;
	// проверить входные данные
	if (len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsValid(theta, len) ||
		!memIsValid(mac, 8))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltMAC_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// выработать имитовставку
	beltMACStart(state, theta, len);
	beltMACStepA(src, count, state);
	beltMACStepG(mac, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Шифрование и имитозащита данных (DWP)
*******************************************************************************
*/

static void beltPolyMul(word c[], const word a[], const word b[], void* stack)
{
	const size_t n = W_OF_B(128);
	word* prod = (word*)stack;
	stack = prod + 2 * n;
	// умножить
	ppMul(prod, a, n, b, n, stack);
	// привести по модулю
	ppRedBelt(prod);
	wwCopy(c, prod, n);
}

static size_t beltPolyMul_deep()
{
	const size_t n = W_OF_B(128);
	return O_OF_W(2 * n) + ppMul_deep(n, n);
}

typedef struct
{
	belt_ctr_st ctr[1];			/*< состояние функций CTR */
	word r[W_OF_B(128)];		/*< переменная r */
	word s[W_OF_B(128)];		/*< переменная s (имитовставка) */
	word len[W_OF_B(128)];		/*< обработано открытых||критических данных */
	octet block[16];			/*< блок данных */
	size_t filled;				/*< накоплено октетов в блоке */
	octet mac[8];				/*< имитовставка для StepV */
	octet stack[];				/*< стек умножения */
} belt_dwp_st;

size_t beltDWP_keep()
{
	return sizeof(belt_dwp_st) + beltPolyMul_deep();
}

void beltDWPStart(void* state, const octet theta[], size_t len, 
	const octet iv[16])
{
	belt_dwp_st* s = (belt_dwp_st*)state;
	ASSERT(memIsDisjoint2(iv, 16, state, beltDWP_keep()));
	// настроить CTR
	beltCTRStart(s->ctr, theta, len, iv);
	// установить r, s
	beltBlockCopy(s->r, s->ctr->ctr);
	beltBlockEncr2((u32*)s->r, s->ctr->key);
#if (OCTET_ORDER == BIG_ENDIAN && B_PER_W != 32)
	beltBlockRevU32(s->r);
	beltBlockRevW(s->r);
#endif
	wwFrom(s->s, beltH(), 16);
	// обнулить счетчики
	memSetZero(s->len, sizeof(s->len));
	s->filled = 0;
}

void beltDWPStepE(void* buf, size_t count, void* state)
{
	beltCTRStepE(buf, count, state);
}

void beltDWPStepI(const void* buf, size_t count, void* state)
{
	belt_dwp_st* s = (belt_dwp_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltDWP_keep()));
	// критические данные не обрабатывались?
	ASSERT(count == 0 || beltHalfBlockIsZero(s->len + W_OF_B(64)));
	// обновить длину
	beltHalfBlockAddBitSizeW(s->len, count);
	// есть накопленные данные?
	if (s->filled)
	{
		if (count < 16 - s->filled)
		{
			memCopy(s->block + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memCopy(s->block + s->filled, buf, 16 - s->filled);
		count -= 16 - s->filled;
		buf = (const octet*)buf + 16 - s->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->s, s->block);
		beltPolyMul(s->s, s->s, s->r, s->stack);
		s->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockCopy(s->block, buf);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->s, s->block);
		beltPolyMul(s->s, s->s, s->r, s->stack);
		buf = (const octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
		memCopy(s->block, buf, s->filled = count);
}

void beltDWPStepA(const void* buf, size_t count, void* state)
{
	belt_dwp_st* s = (belt_dwp_st*)state;
	ASSERT(memIsDisjoint2(buf, count, state, beltDWP_keep()));
	// первый непустой фрагмент критических данных?
	// есть необработанные открытые данные?
	if (count && beltHalfBlockIsZero(s->len + W_OF_B(64)) && s->filled)
	{
		memSetZero(s->block + s->filled, 16 - s->filled);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->s, s->block);
		beltPolyMul(s->s, s->s, s->r, s->stack);
		s->filled = 0;
	}
	// обновить длину
	beltHalfBlockAddBitSizeW(s->len + W_OF_B(64), count);
	// есть накопленные данные?
	if (s->filled)
	{
		if (count < 16 - s->filled)
		{
			memCopy(s->block + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memCopy(s->block + s->filled, buf, 16 - s->filled);
		count -= 16 - s->filled;
		buf = (const octet*)buf + 16 - s->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->s, s->block);
		beltPolyMul(s->s, s->s, s->r, s->stack);
		s->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 16)
	{
		beltBlockCopy(s->block, buf);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->s, s->block);
		beltPolyMul(s->s, s->s, s->r, s->stack);
		buf = (const octet*)buf + 16;
		count -= 16;
	}
	// неполный блок?
	if (count)
		memCopy(s->block, buf, s->filled = count);
}

void beltDWPStepD(void* buf, size_t count, void* state)
{
	beltCTRStepD(buf, count, state);
}

static void beltDWPStepG_internal(void* state)
{
	belt_dwp_st* s = (belt_dwp_st*)state;
	ASSERT(memIsValid(state, beltDWP_keep()));
	// есть накопленные данные?
	if (s->filled)
	{
		memSetZero(s->block + s->filled, 16 - s->filled);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevW(s->block);
#endif
		beltBlockXor2(s->s, s->block);
		beltPolyMul(s->s, s->s, s->r, s->stack);
		s->filled = 0;
	}
	// обработать блок длины
	beltBlockXor2(s->s, s->len);
	beltPolyMul(s->s, s->s, s->r, s->stack);
#if (OCTET_ORDER == BIG_ENDIAN && B_PER_W != 32)
	beltBlockRevW(s->s);
	beltBlockRevU32(s->s);
#endif
	beltBlockEncr2((u32*)s->s, s->ctr->key);
}

void beltDWPStepG(octet mac[8], void* state)
{
	belt_dwp_st* s = (belt_dwp_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltDWPStepG_internal(state);
	u32To(mac, 8, (u32*)s->s);
}

bool_t beltDWPStepV(const octet mac[8], void* state)
{
	belt_dwp_st* s = (belt_dwp_st*)state;
	ASSERT(memIsValid(mac, 8));
	beltDWPStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	s->s[0] = u32Rev(s->s[0]);
	s->s[1] = u32Rev(s->s[1]);
#endif
	return memEq(mac, s->s, 8);
}

err_t beltDWPWrap(void* dest, octet mac[8], const void* src1, size_t count1,
	const void* src2, size_t count2, const octet theta[], size_t len,
	const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (len != 16 && len != 24 && len != 32 ||
		!memIsValid(src1, count1) ||
		!memIsValid(src2, count2) ||
		!memIsValid(theta, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count1) ||
		!memIsValid(mac, 8))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltDWP_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// установить защиту
	beltDWPStart(state, theta, len, iv);
	beltDWPStepI(src2, count2, state);
	memMove(dest, src1, count1);
	beltDWPStepE(dest, count1, state);
	beltDWPStepA(dest, count1, state);
	beltDWPStepG(mac, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltDWPUnwrap(void* dest, const void* src1, size_t count1,
	const void* src2, size_t count2, const octet mac[8], const octet theta[],
	size_t len, const octet iv[16])
{
	void* state;
	// проверить входные данные
	if (len != 16 && len != 24 && len != 32 ||
		!memIsValid(src1, count1) ||
		!memIsValid(src2, count2) ||
		!memIsValid(mac, 8) ||
		!memIsValid(theta, len) ||
		!memIsValid(iv, 16) ||
		!memIsValid(dest, count1))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltDWP_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// снять защиту
	beltDWPStart(state, theta, len, iv);
	beltDWPStepI(src2, count2, state);
	beltDWPStepA(src1, count1, state);
	if (!beltDWPStepV(mac, state))
	{
		blobClose(state);
		return ERR_BAD_MAC;
	}
	memMove(dest, src1, count1);
	beltDWPStepD(dest, count1, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Шифрование и имитозащита ключей (KWP)
*******************************************************************************
*/
typedef struct
{
	u32 key[8];			/*< форматированный ключ */
	octet block[16];		/*< вспомогательный блок */
	word round;				/*< номер такта */
} belt_kwp_st;

size_t beltKWP_keep()
{
	return sizeof(belt_kwp_st);
}

void beltKWPStart(void* state, const octet theta[], size_t len)
{
	belt_kwp_st* s = (belt_kwp_st*)state;
	ASSERT(memIsValid(state, beltKWP_keep()));
	beltKeyExpand2(s->key, theta, len);
	s->round = 0;
}

void beltKWPStepE(void* buf, size_t count, void* state)
{
	belt_kwp_st* s = (belt_kwp_st*)state;
	word n = ((word)count + 15) / 16;
	ASSERT(count >= 32);
	ASSERT(memIsDisjoint2(buf, count, state, beltKWP_keep()));
	do
	{
		size_t i;
		// block <- r1 + ... + r_{n-1}
		beltBlockCopy(s->block, buf);
		for (i = 16; i + 16 < count; i += 16)
			beltBlockXor2(s->block, (octet*)buf + i);
		// r <- ShLo^128(r)
		memMove(buf, (octet*)buf + 16, count - 16);
		// r* <- block
		beltBlockCopy((octet*)buf + count - 16, s->block);
		// block <- beltBlockEncr(block) + <round>
		beltBlockEncr(s->block, s->key);
		s->round++;
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(s->block, &s->round, O_PER_W);
#else // BIG_ENDIAN
		s->round = wordRev(s->round);
		memXor2(s->block, &s->round, O_PER_W);
		s->round = wordRev(s->round);
#endif // OCTET_ORDER
		// r*_до_сдвига <- r*_до_сдвига + block
		beltBlockXor2((octet*)buf + count - 32, s->block);
	}
	while (s->round % (2 * n));
}

void beltKWPStepD(void* buf, size_t count, void* state)
{
	belt_kwp_st* s = (belt_kwp_st*)state;
	word n = ((word)count + 15) / 16;
	ASSERT(count >= 32);
	ASSERT(memIsDisjoint2(buf, count, state, beltKWP_keep()));
	for (s->round = 2 * n; s->round; --s->round)
	{
		size_t i;
		// block <- r*
		beltBlockCopy(s->block, (octet*)buf + count - 16);
		// r <- ShHi^128(r)
		memMove((octet*)buf + 16, buf, count - 16);
		// r1 <- block
		beltBlockCopy(buf, s->block);
		// block <- beltBlockEncr(block) + <round>
		beltBlockEncr(s->block, s->key);
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(s->block, &s->round, O_PER_W);
#else // BIG_ENDIAN
		s->round = wordRev(s->round);
		memXor2(s->block, &s->round, O_PER_W);
		s->round = wordRev(s->round);
#endif // OCTET_ORDER
		// r* <- r* + block
		beltBlockXor2((octet*)buf + count - 16, s->block);
		// r1 <- r1 + r2 + ... + r_{n-1}
		for (i = 16; i + 16 < count; i += 16)
			beltBlockXor2(buf, (octet*)buf + i);
	}
}

void beltKWPStepD2(void* buf1, void* buf2, size_t count, void* state)
{
	belt_kwp_st* s = (belt_kwp_st*)state;
	word n = ((word)count + 15) / 16;
	ASSERT(count >= 32);
	ASSERT(memIsDisjoint3(buf1, count - 16, buf2, 16, state, beltKWP_keep()));
	for (s->round = 2 * n; s->round; --s->round)
	{
		size_t i;
		// block <- r*
		beltBlockCopy(s->block, buf2);
		// r <- ShHi^128(r)
		memCopy(buf2, (octet*)buf1 + count - 32, 16);
		memMove((octet*)buf1 + 16, buf1, count - 32);
		// r1 <- block
		beltBlockCopy(buf1, s->block);
		// block <- beltBlockEncr(block) + <round>
		beltBlockEncr(s->block, s->key);
#if (OCTET_ORDER == LITTLE_ENDIAN)
		memXor2(s->block, &s->round, O_PER_W);
#else // BIG_ENDIAN
		s->round = wordRev(s->round);
		memXor2(s->block, &s->round, O_PER_W);
		s->round = wordRev(s->round);
#endif // OCTET_ORDER
		// r* <- r* + block
		beltBlockXor2(buf2, s->block);
		// r1 <- r1 + r2 + ... + r_{n-1}
		for (i = 16; i + 32 < count; i += 16)
			beltBlockXor2(buf1, (octet*)buf1 + i);
		ASSERT(i + 16 <= count && i + 32 >= count);
		if (i + 16 < count)
		{
			memXor2(buf1, (octet*)buf1 + i, count - 16 - i);
			memXor2((octet*)buf1 + count - 16 - i, buf2, 32 + i - count);
		}
	}
}

err_t beltKWPWrap(octet dest[], const octet src[], size_t count,
	const octet header[16], const octet theta[], size_t len)
{
	void* state;
	// проверить входные данные
	if (count < 16 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsNullOrValid(header, 16) ||
		header && !memIsDisjoint2(src, count, header, 16) ||
		!memIsValid(theta, len) ||
		!memIsValid(dest, count + 16))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltKWP_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// установить защиту
	beltKWPStart(state, theta, len);
	memMove(dest, src, count);
	if (header)
		memJoin(dest, src, count, header, 16);
	else
		memMove(dest, src, count),
		memSetZero(dest + count, 16);
	beltKWPStepE(dest, count + 16, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

err_t beltKWPUnwrap(octet dest[], const octet src[], size_t count,
	const octet header[16], const octet theta[], size_t len)
{
	void* state;
	octet* header2;
	// проверить входные данные
	if (count < 32 ||
		len != 16 && len != 24 && len != 32 ||
		!memIsValid(src, count) ||
		!memIsNullOrValid(header, 16) ||
		!memIsValid(theta, len) ||
		!memIsValid(dest, count - 16))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltKWP_keep() + 16);
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	header2 = (octet*)state + beltKWP_keep();
	// снять защиту
	beltKWPStart(state, theta, len);
	memCopy(header2, src + count - 16, 16);
	memMove(dest, src, count - 16);
	beltKWPStepD2(dest, header2, count, state);
	if (header && !memEq(header, header2, 16) ||
		header == 0 && !memIsZero(header2, 16))
	{
		memSetZero(dest, count - 16);
		blobClose(state);
		return ERR_BAD_KEYTOKEN;
	}
	// завершить
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Преобразования sigma1, sigma2

В функции beltSigma реализованы преобразования sigma1, sigma2 (п. 6.9.2):
	s <- s + sigma1(X || h), h <- sigma2(X || h).
В функции beltSigma2 реализовано только преобразование sigma2.

h и X разбиваются на половинки:
	[8]h = [4]h0 || [4]h1, [8]X = [4]X0 || [4]X1.

\pre Буферы s и h, s и X, h и X не пересекаются.

Схема расчета глубины стека:
		beltSigma_deep().
*******************************************************************************
*/

static void beltSigma(u32 s[4], u32 h[8], const u32 X[8], void* stack)
{
	// [12]buf = [4]buf0 || [4]buf1 || [4]buf2
	u32* buf = (u32*)stack;
	// буферы не пересекаются?
	ASSERT(memIsDisjoint4(s, 16, h, 32, X, 32, buf, 48));
	// buf0, buf1 <- h0 + h1
	beltBlockXor(buf, h, h + 4);
	beltBlockCopy(buf + 4, buf);
	// buf0 <- beltBlock(buf0, X) + buf1
	beltBlockEncr2(buf, X);
	beltBlockXor2(buf, buf + 4);
	// s <- s ^ buf0
	beltBlockXor2(s, buf);
	// buf2 <- h0
	beltBlockCopy(buf + 8, h);
	// buf1 <- h1 [buf01 == theta1]
	beltBlockCopy(buf + 4, h + 4);
	// h0 <- beltBlock(X0, buf01) + X0
	beltBlockCopy(h, X);
	beltBlockEncr2(h, buf);
	beltBlockXor2(h, X);
	// buf1 <- ~buf0 [buf12 == theta2]
	beltBlockNeg(buf + 4, buf);
	// h1 <- beltBlock(X1, buf12) + X1
	beltBlockCopy(h + 4, X + 4);
	beltBlockEncr2(h + 4, buf + 4);
	beltBlockXor2(h + 4, X + 4);
}

static void beltSigma2(u32 h[8], const u32 X[8], void* stack)
{
	// [12]buf = [4]buf0 || [4]buf1 || [4]buf2
	u32* buf = (u32*)stack;
	// буферы не пересекаются?
	ASSERT(memIsDisjoint3(h, 32, X, 32, buf, 48));
	// buf0, buf1 <- h0 + h1
	beltBlockXor(buf, h, h + 4);
	beltBlockCopy(buf + 4, buf);
	// buf0 <- beltBlock(buf0, X) + buf1
	beltBlockEncr2(buf, X);
	beltBlockXor2(buf, buf + 4);
	// buf2 <- h0
	beltBlockCopy(buf + 8, h);
	// buf1 <- h1 [buf01 == theta1]
	beltBlockCopy(buf + 4, h + 4);
	// h0 <- beltBlock(X0, buf01) + X0
	beltBlockCopy(h, X);
	beltBlockEncr2(h, buf);
	beltBlockXor2(h, X);
	// buf1 <- ~buf0 [buf12 == theta2]
	beltBlockNeg(buf + 4, buf);
	// h1 <- beltBlock(X1, buf12) + X1
	beltBlockCopy(h + 4, X + 4);
	beltBlockEncr2(h + 4, buf + 4);
	beltBlockXor2(h + 4, X + 4);
}

static size_t beltSigma_deep()
{
	return 12 * 4;
}

/*
*******************************************************************************
Хэширование

\remark Копии переменных хранятся для организации инкрементального хэширования.
*******************************************************************************
*/
typedef struct {
	u32 ls[8];			/*< блок [4]len || [4]s */
	u32 s1[4];			/*< копия переменной s */
	u32 h[8];			/*< переменная h */
	u32 h1[8];			/*< копия переменной h */
	octet block[32];		/*< блок данных */
	size_t filled;			/*< накоплено октетов в блоке */
	octet stack[];			/*< [beltSigma_deep()] стек beltSigma */
} belt_hash_st;

size_t beltHash_keep()
{
	return sizeof(belt_hash_st) + beltSigma_deep();
}

void beltHashStart(void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(memIsValid(s, beltHash_keep()));
	// len || s <- 0
	beltBlockSetZero(s->ls);
	beltBlockSetZero(s->ls + 4);
	// h <- B194...0D
	u32From(s->h, beltH(), 32);
	// нет накопленнных данных
	s->filled = 0;
}

void beltHashStepH(const void* buf, size_t count, void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, beltHash_keep()));
	// обновить длину
	beltBlockAddBitSizeU32(s->ls, count);
	// есть накопленные данные?
	if (s->filled)
	{
		if (count < 32 - s->filled)
		{
			memCopy(s->block + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memCopy(s->block + s->filled, buf, 32 - s->filled);
		count -= 32 - s->filled;
		buf = (const octet*)buf + 32 - s->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltSigma(s->ls + 4, s->h, (u32*)s->block, s->stack);
		s->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 32)
	{
		beltBlockCopy(s->block, buf);
		beltBlockCopy(s->block + 16, (const octet*)buf + 16);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltSigma(s->ls + 4, s->h, (u32*)s->block, s->stack);
		buf = (const octet*)buf + 32;
		count -= 32;
	}
	// неполный блок?
	if (count)
		memCopy(s->block, buf, s->filled = count);
}

static void beltHashStepG_internal(void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	// pre
	ASSERT(memIsValid(s, beltHash_keep()));
	// создать копии второй части s->ls и s->h
	beltBlockCopy(s->s1, s->ls + 4);
	beltBlockCopy(s->h1, s->h);
	beltBlockCopy(s->h1 + 4, s->h + 4);
	// есть необработанные данные?
	if (s->filled)
	{
		memSetZero(s->block + s->filled, 32 - s->filled);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltSigma(s->ls + 4, s->h1, (u32*)s->block, s->stack);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block + 16);
		beltBlockRevU32(s->block);
#endif
	}
	// последний блок
	beltSigma2(s->h1, s->ls, s->stack);
	// восстановить сохраненную часть s->ls
	beltBlockCopy(s->ls + 4, s->s1);
}

void beltHashStepG(octet hash[32], void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(memIsValid(hash, 32));
	beltHashStepG_internal(state);
	u32To(hash, 32, s->h1);
}

void beltHashStepG2(octet hash[], size_t hash_len, void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(hash_len <= 32);
	ASSERT(memIsValid(hash, hash_len));
	beltHashStepG_internal(state);
	u32To(hash, hash_len, s->h1);
}

bool_t beltHashStepV(const octet hash[32], void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(memIsValid(hash, 32));
	beltHashStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(s->h1);
	beltBlockRevU32(s->h1 + 4);
#endif
	return memEq(hash, s->h1, 32);
}

bool_t beltHashStepV2(const octet hash[], size_t hash_len, void* state)
{
	belt_hash_st* s = (belt_hash_st*)state;
	ASSERT(hash_len <= 32);
	ASSERT(memIsValid(hash, hash_len));
	beltHashStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(s->h1);
	beltBlockRevU32(s->h1 + 4);
#endif
	return memEq(hash, s->h1, hash_len);
}

err_t beltHash(octet hash[32], const void* src, size_t count)
{
	void* state;
	// проверить входные данные
	if (!memIsValid(src, count) || !memIsValid(hash, 32))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltHash_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// вычислить хэш-значение
	beltHashStart(state);
	beltHashStepH(src, count, state);
	beltHashStepG(hash, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Преобразование ключа
*******************************************************************************
*/

typedef struct {
	u32 key[8];		/*< форматированный первоначальный ключ */
	size_t len;			/*< длина первоначального ключа */
	u32 block[8];	/*< блок r || level || header */
	u32 key_new[8];	/*< форматированный преобразованный ключ */
	octet stack[];		/*< стек beltSigma */
} belt_krp_st;

size_t beltKRP_keep()
{
	return sizeof(belt_krp_st) + beltSigma_deep();
}

void beltKRPStart(void* state, const octet theta[], size_t len, const octet level[12])
{
	belt_krp_st* s = (belt_krp_st*)state;
	ASSERT(memIsDisjoint2(level, 12, s, beltKRP_keep()));
	// block <- ... || level || ...
	u32From(s->block + 1, level, 12);
	// сохранить ключ
	beltKeyExpand2(s->key, theta, s->len = len);
}

void beltKRPStepG(octet key[], size_t key_len, const octet header[16],
	void* state)
{
	belt_krp_st* s = (belt_krp_st*)state;
	// pre
	ASSERT(memIsValid(s, beltKRP_keep()));
	ASSERT(key_len == 16 || key_len == 24 || key_len == 32);
	ASSERT(key_len <= s->len);
	ASSERT(memIsDisjoint2(key, key_len, s, beltKRP_keep()));
	ASSERT(memIsDisjoint2(header, 16, s, beltKRP_keep()));
	// полностью определить s->block
	u32From(s->block, beltH() + 4 * (s->len - 16) + 2 * (key_len - 16), 4);
	u32From(s->block + 4, header, 16);
	// применить sigma2
	beltBlockCopy(s->key_new, s->key);
	beltBlockCopy(s->key_new + 4, s->key + 4);
	beltSigma2(s->key_new, s->block, s->stack);
	// выгрузить ключ
	u32To(key, key_len, s->key_new);
}

err_t beltKRP(octet dest[], size_t m, const octet src[], size_t n,
	const octet level[12], const octet header[16])
{
	void* state;
	// проверить входные данные
	if (m > n ||
		m != 16 && m != 24 && m != 32 ||
		n != 16 && n != 24 && n != 32 ||
		!memIsValid(src, n) ||
		!memIsValid(level, 12) ||
		!memIsValid(header, 16) ||
		!memIsValid(dest, m))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltKRP_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// преобразовать ключ
	beltKRPStart(state, src, n, level);
	beltKRPStepG(dest, m, header, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Ключезависимое хэширование (HMAC)
*******************************************************************************
*/
typedef struct
{
	u32 ls_in[8];	/*< блок [4]len || [4]s внутреннего хэширования */
	u32 h_in[8];		/*< переменная h внутреннего хэширования */
	u32 h1_in[8];	/*< копия переменной h внутреннего хэширования */
	u32 ls_out[8];	/*< блок [4]len || [4]s внешнего хэширования */
	u32 h_out[8];	/*< переменная h внешнего хэширования */
	u32 h1_out[8];	/*< копия переменной h внешнего хэширования */
	u32 s1[4];		/*< копия переменной s */
	octet block[32];	/*< блок данных */
	size_t filled;		/*< накоплено октетов в блоке */
	octet stack[];		/*< [beltSigma_deep()] стек beltSigma */
} belt_hmac_st;

size_t beltHMAC_keep()
{
	return sizeof(belt_hmac_st) + beltSigma_deep();
}

void beltHMACStart(void* state, const octet theta[], size_t len)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(memIsDisjoint2(theta, len, s, beltHMAC_keep()));
	// key <- theta || 0
	if (len <= 32)
	{
		memCopy(s->block, theta, len);
		memSetZero(s->block + len, 32 - len);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
	}
	// key <- beltHash(theta)
	else
	{
		beltBlockSetZero(s->ls_in);
		beltBlockAddBitSizeU32(s->ls_in, len);
		beltBlockSetZero(s->ls_in + 4);
		u32From(s->h_in, beltH(), 32);
		while (len >= 32)
		{
			beltBlockCopy(s->block, theta);
			beltBlockCopy(s->block + 16, theta + 16);
#if (OCTET_ORDER == BIG_ENDIAN)
			beltBlockRevU32(s->block);
			beltBlockRevU32(s->block + 16);
#endif
			beltSigma(s->ls_in + 4, s->h_in, (u32*)s->block, s->stack);
			theta += 32;
			len -= 32;
		}
		if (len)
		{
			memCopy(s->block, theta, len);
			memSetZero(s->block + len, 32 - len);
#if (OCTET_ORDER == BIG_ENDIAN)
			beltBlockRevU32(s->block);
			beltBlockRevU32(s->block + 16);
#endif
			beltSigma(s->ls_in + 4, s->h_in, (u32*)s->block, s->stack);
		}
		beltSigma2(s->h_in, s->ls_in, s->stack);
		beltBlockCopy(s->block, s->h_in);
		beltBlockCopy(s->block + 16, s->h_in + 4);
	}
	// сформировать key ^ ipad
	for (len = 0; len < 32; ++len)
		s->block[len] ^= 0x36;
	// начать внутреннее хэширование
	beltBlockSetZero(s->ls_in);
	beltBlockAddBitSizeU32(s->ls_in, 32);
	beltBlockSetZero(s->ls_in + 4);
	u32From(s->h_in, beltH(), 32);
	beltSigma(s->ls_in + 4, s->h_in, (u32*)s->block, s->stack);
	s->filled = 0;
	// сформировать key ^ opad [0x36 ^ 0x5C == 0x6A]
	for (; len--; )
	s->block[len] ^= 0x6A;
	// начать внешнее хэширование [будет хэшироваться ровно два блока]
	beltBlockSetZero(s->ls_out);
	beltBlockAddBitSizeU32(s->ls_out, 32 * 2);
	beltBlockSetZero(s->ls_out + 4);
	u32From(s->h_out, beltH(), 32);
	beltSigma(s->ls_out + 4, s->h_out, (u32*)s->block, s->stack);
}

void beltHMACStepA(const void* buf, size_t count, void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, beltHMAC_keep()));
	// обновить длину
	beltBlockAddBitSizeU32(s->ls_in, count);
	// есть накопленные данные?
	if (s->filled)
	{
		if (count < 32 - s->filled)
		{
			memCopy(s->block + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memCopy(s->block + s->filled, buf, 32 - s->filled);
		count -= 32 - s->filled;
		buf = (const octet*)buf + 32 - s->filled;
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltSigma(s->ls_in + 4, s->h_in, (u32*)s->block, s->stack);
		s->filled = 0;
	}
	// цикл по полным блокам
	while (count >= 32)
	{
		beltBlockCopy(s->block, buf);
		beltBlockCopy(s->block + 16, (const octet*)buf + 16);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltSigma(s->ls_in + 4, s->h_in, (u32*)s->block, s->stack);
		buf = (const octet*)buf + 32;
		count -= 32;
	}
	// неполный блок?
	if (count)
		memCopy(s->block, buf, s->filled = count);
}

static void beltHMACStepG_internal(void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	// pre
	ASSERT(memIsValid(s, beltHash_keep()));
	// создать копии второй части s->ls_in и s->h_in
	beltBlockCopy(s->s1, s->ls_in + 4);
	beltBlockCopy(s->h1_in, s->h_in);
	beltBlockCopy(s->h1_in + 4, s->h_in + 4);
	// есть необработанные данные?
	if (s->filled)
	{
		memSetZero(s->block + s->filled, 32 - s->filled);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block);
		beltBlockRevU32(s->block + 16);
#endif
		beltSigma(s->ls_in + 4, s->h1_in, (u32*)s->block, s->stack);
#if (OCTET_ORDER == BIG_ENDIAN)
		beltBlockRevU32(s->block + 16);
		beltBlockRevU32(s->block);
#endif
	}
	// последний блок внутреннего хэширования
	beltSigma2(s->h1_in, s->ls_in, s->stack);
	// восстановить сохраненную часть s->ls_in
	beltBlockCopy(s->ls_in + 4, s->s1);
	// создать копии второй части s->ls_out и s->h_out
	beltBlockCopy(s->s1, s->ls_out + 4);
	beltBlockCopy(s->h1_out, s->h_out);
	beltBlockCopy(s->h1_out + 4, s->h_out + 4);
	// обработать блок s->h1_in
	beltSigma(s->ls_out + 4, s->h1_out, s->h1_in, s->stack);
	// последний блок внешнего хэширования
	beltSigma2(s->h1_out, s->ls_out, s->stack);
	// восстановить сохраненную часть s->ls_out
	beltBlockCopy(s->ls_out + 4, s->s1);
}

void beltHMACStepG(octet mac[32], void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(memIsValid(mac, 32));
	beltHMACStepG_internal(state);
	u32To(mac, 32, s->h1_out);
}

void beltHMACStepG2(octet mac[], size_t mac_len, void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(mac_len <= 32);
	ASSERT(memIsValid(mac, mac_len));
	beltHMACStepG_internal(state);
	u32To(mac, mac_len, s->h1_out);
}

bool_t beltHMACStepV(const octet mac[32], void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(memIsValid(mac, 32));
	beltHMACStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(s->h1_out);
	beltBlockRevU32(s->h1_out + 4);
#endif
	return memEq(mac, s->h1_out, 32);
}

bool_t beltHMACStepV2(const octet mac[], size_t mac_len, void* state)
{
	belt_hmac_st* s = (belt_hmac_st*)state;
	ASSERT(mac_len <= 32);
	ASSERT(memIsValid(mac, mac_len));
	beltHMACStepG_internal(state);
#if (OCTET_ORDER == BIG_ENDIAN)
	beltBlockRevU32(s->h1_out);
	beltBlockRevU32(s->h1_out + 4);
#endif
	return memEq(mac, s->h1_out, mac_len);
}

err_t beltHMAC(octet mac[32], const void* src, size_t count,
	const octet theta[], size_t len)
{
	void* state;
	// проверить входные данные
	if (!memIsValid(src, count) ||
		!memIsValid(theta, len) ||
		!memIsValid(mac, 32))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltHMAC_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// выработать имитовставку
	beltHMACStart(state, theta, len);
	beltHMACStepA(src, count, state);
	beltHMACStepG(mac, state);
	// завершить
	blobClose(state);
	return ERR_OK;
}

/*
*******************************************************************************
Построение ключа по паролю
*******************************************************************************
*/

err_t beltPBKDF(octet theta[32], const octet pwd[], size_t pwd_len,
	size_t iter, const octet salt[], size_t salt_len)
{
	void* state;
	// проверить входные данные
	if (iter == 0 ||
		!memIsValid(pwd, pwd_len) ||
		!memIsValid(salt, salt_len) ||
		!memIsValid(theta, 32))
		return ERR_BAD_INPUT;
	// создать состояние
	state = blobCreate(beltHMAC_keep());
	if (state == 0)
		return ERR_NOT_ENOUGH_MEMORY;
	// theta <- HMAC(pwd, salt || 00000001)
	beltHMACStart(state, pwd, pwd_len);
	beltHMACStepA(salt, salt_len, state);
	*(u32*)theta = 0, theta[3] = 1;
	beltHMACStepA(theta, 4, state);
	beltHMACStepG(theta, state);
	// пересчитать theta
	while (iter--)
	{
		beltHMACStart(state, pwd, pwd_len);
		beltHMACStepA(theta, 32, state);
		beltHMACStepG(theta, state);
	}
	// завершить
	blobClose(state);
	return ERR_OK;
}
