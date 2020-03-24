/*
*******************************************************************************
\file belt_lcl.h
\brief STB 34.101.31 (belt): local definitions
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.12.18
\version 2020.03.20
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#ifndef __BELT_LCL_H
#define __BELT_LCL_H

#include "bee2/core/word.h"
#include "bee2/core/u32.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
*******************************************************************************
Замечание по интерфейсам

Состояния некоторых связок (например, beltHash) содержат память, которую 
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

/*
*******************************************************************************
Состояния CTR и WBL (используются в DWP, KWP и FMT)
*******************************************************************************
*/

typedef struct
{
	u32 key[8];			/*< форматированный ключ */
	u32 ctr[4];			/*< счетчик */
	octet block[16];	/*< блок гаммы */
	size_t reserved;	/*< резерв октетов гаммы */
} belt_ctr_st;

typedef struct
{
	u32 key[8];			/*< форматированный ключ */
	octet block[16];	/*< вспомогательный блок */
	octet sum[16];		/*< вспомогательная сумма блоков */
	word round;			/*< номер такта */
} belt_wbl_st;

/*
*******************************************************************************
Вспомогательные функции
*******************************************************************************
*/

void beltBlockAddBitSizeU32(u32 block[4], size_t count);
void beltHalfBlockAddBitSizeW(word block[W_OF_B(64)], size_t count);
void beltPolyMul(word c[], const word a[], const word b[], void* stack);
size_t beltPolyMul_deep();
void beltBlockMulC(u32 block[4]);



#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BELT_LCL_H */
