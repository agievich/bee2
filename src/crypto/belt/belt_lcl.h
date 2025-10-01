/*
*******************************************************************************
\file belt_lcl.h
\brief STB 34.101.31 (belt): local definitions
\project bee2 [cryptographic library]
\created 2012.12.18
\version 2025.10.01
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
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
Операции с блоками

Реализованы операции над блоками и полублоками belt. Блок представляется либо 
как [16]octet, либо как [4]u32, либо как [W_OF_O(16)]word.

Суффикс U32 в именах макросов и функций означает, что данные интерпретируются
как массив u32. Суффикс W означает, что данные интерпретируются как
массив word.

\remark Блок не обязательно выровнен на границу word или u32. 
\todo Работу с блоками можно ускорить, если предположить выравнивание (в 
качестве предусловия).
*******************************************************************************
*/

#define beltBlockSetZero(block)\
	memSetZero(block, 16)

#define beltBlockNeg(dest, src)\
	(memCopy(dest, src, 16), memNeg(dest, 16))

#define beltBlockXor(dest, src1, src2)\
	memXor(dest, src1, src2, 16)

#define beltBlockXor2(dest, src)\
	memXor2(dest, src, 16)

#define beltHalfBlockIsZero(block)\
	memIsZero(block, 8)

#define beltBlockCopy(dest, src)\
	memCopy(dest, src, 16)

#if (B_PER_W == 16)

#define beltBlockRevW(block) {\
	ASSERT(memIsAligned(block, O_PER_W));\
	((word*)(block))[0] = wordRev(((word*)(block))[0]);\
	((word*)(block))[1] = wordRev(((word*)(block))[1]);\
	((word*)(block))[2] = wordRev(((word*)(block))[2]);\
	((word*)(block))[3] = wordRev(((word*)(block))[3]);\
	((word*)(block))[4] = wordRev(((word*)(block))[4]);\
	((word*)(block))[5] = wordRev(((word*)(block))[5]);\
	((word*)(block))[6] = wordRev(((word*)(block))[6]);\
	((word*)(block))[7] = wordRev(((word*)(block))[7]);\
}

#elif (B_PER_W == 32)

#define beltBlockRevW(block) {\
	ASSERT(memIsAligned(block, O_PER_W));\
	((word*)(block))[0] = wordRev(((word*)(block))[0]);\
	((word*)(block))[1] = wordRev(((word*)(block))[1]);\
	((word*)(block))[2] = wordRev(((word*)(block))[2]);\
	((word*)(block))[3] = wordRev(((word*)(block))[3]);\
}

#elif (B_PER_W == 64)

#define beltBlockRevW(block) {\
	ASSERT(memIsAligned(block, O_PER_W));\
	((word*)(block))[0] = wordRev(((word*)(block))[0]);\
	((word*)(block))[1] = wordRev(((word*)(block))[1]);\
}

#else
	#error "Unsupported word size"
#endif // B_PER_W

#define beltBlockRevU32(block) {\
	ASSERT(memIsAligned(block, 4));\
	((u32*)(block))[0] = u32Rev(((u32*)(block))[0]);\
	((u32*)(block))[1] = u32Rev(((u32*)(block))[1]);\
	((u32*)(block))[2] = u32Rev(((u32*)(block))[2]);\
	((u32*)(block))[3] = u32Rev(((u32*)(block))[3]);\
}

#define beltBlockIncU32(block) {\
	ASSERT(memIsAligned(block, 4));\
	if ((((u32*)(block))[0] += 1) == 0 &&\
		(((u32*)(block))[1] += 1) == 0 &&\
		(((u32*)(block))[2] += 1) == 0)\
		((u32*)(block))[3] += 1;\
}

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
