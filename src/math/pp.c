/*
*******************************************************************************
\file pp.c
\brief Binary polynomials
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.03.01
\version 2016.05.18
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/math/pp.h"
#include "bee2/math/ww.h"

/*	подавить предупреждение C4146
	[unary minus operator applied to unsigned type, result still unsigned]
	[см. макросы _MUL_REPAIR_XX]
*/

#if defined (_MSC_VER) && (_MSC_VER >= 1200)
	#pragma warning(push)
	#pragma warning(disable:4146)
#endif

/*
*******************************************************************************
Степень
*******************************************************************************
*/

size_t ppDeg(const word a[], size_t n)
{
	return wwBitSize(a, n) - SIZE_1;
}

/*
*******************************************************************************
Макросы умножения многочленов из одного слова

Макросы реализуют алгоритмы из работы
	[Brent, Gaudry, Thome, Zimmerman. Faster Multiplication in GF(2)[x],
	http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.134.583, 2007]
с длинами окон s = 2, 3, 4.

В макросах используются следующие обозначения:
	a, b -- множители, (hi, lo) -- произведение,
	w -- вспомогательная таблица младших слов первых 2^s кратных a (окно).

На платформе Intel Core2 Duo CPU E8400 максимальная производительность
достигается при s = 4.
*******************************************************************************
*/

#define _MUL_PRE_S2(t, a)\
	(t)[0] = 0;\
	(t)[1] = (a);\
	(t)[2] = (t)[1] << 1;\
	(t)[3] = (t)[2] ^ (a);\

#define _MUL_PRE_S3(t, a)\
	_MUL_PRE_S2(t, a)\
	(t)[4] = (t)[2] << 1;\
	(t)[5] = (t)[4] ^ (a);\
	(t)[6] = (t)[3] << 1;\
	(t)[7] = (t)[6] ^ (a);\

#define _MUL_PRE_S4(t, a)\
	_MUL_PRE_S3(t, a)\
	(t)[8] = (t)[4] << 1;\
	(t)[9] = (t)[8] ^ (a);\
	(t)[10] = (t)[5] << 1;\
	(t)[11] = (t)[10] ^ (a);\
	(t)[12] = (t)[6] << 1;\
	(t)[13] = (t)[12] ^ (a);\
	(t)[14] = (t)[7] << 1;\
	(t)[15] = (t)[14] ^ (a);\

#if (B_PER_W == 16)

#define _MUL_MUL_S2(lo, hi, t, b)\
	(lo) = (t)[(b) >> 14] << 2 ^ (t)[(b) >> 12 & 3];\
	(hi) = (lo) >> 12;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 10 & 3] << 2 ^ (t)[(b) >> 8 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 12;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 6 & 3] << 2 ^ (t)[(b) >> 4 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 12;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 2 & 3] << 2 ^ (t)[(b) & 3];\

#define _MUL_MUL_S3(lo, hi, t, b)\
   (lo) = (t)[(b) >> 15] << 3 ^ (t)[(b) >> 12 & 7];\
   (hi) = (lo) >> 10;\
   (lo) = (lo) << 6 ^ (t)[(b) >> 9 & 7] << 3 ^ (t)[(b) >> 6 & 7];\
   (hi) = (hi) << 6 ^ (lo) >> 10;\
   (lo) = (lo) << 6 ^ (t)[(b) >> 3 & 7] << 3 ^ (t)[(b) & 7];\

#define _MUL_MUL_S4(lo, hi, t, b)\
	(lo) = (t)[(b) >> 12] << 4 ^ (t)[(b) >> 8 & 15];\
	(hi) = (lo) >> 8;\
	(lo) = (lo) << 8 ^ (t)[(b) >> 4 & 15] << 4 ^ (t)[(b) & 15];\

#define _MUL_REPAIR_S2(hi, a, b)\
	(hi) ^= ((b) & 0xEEEE) >> 1 & -((a) >> 15);\
	(hi) ^= ((b) & 0xCCCC) >> 2 & -((a) >> 14 & 1);\
	(hi) ^= ((b) & 0x8888) >> 3 & -((a) >> 13 & 1);\

#define _MUL_REPAIR_S3(hi, a, b)\
	(hi) ^= ((b) & 0xEFBE) >> 1 & -((a) >> 15);\
	(hi) ^= ((b) & 0xCF3C) >> 2 & -((a) >> 14 & 1);\
	(hi) ^= ((b) & 0x8E38) >> 3 & -((a) >> 13 & 1);\
	(hi) ^= ((b) & 0x0C30) >> 4 & -((a) >> 12 & 1);\
	(hi) ^= ((b) & 0x0820) >> 5 & -((a) >> 11 & 1);\

#define _MUL_REPAIR_S4(hi, a, b)\
	(hi) ^= ((b) & 0xFEFE) >> 1 & -((a) >> 15);\
	(hi) ^= ((b) & 0xFCFC) >> 2 & -((a) >> 14 & 1);\
	(hi) ^= ((b) & 0xF8F8) >> 3 & -((a) >> 13 & 1);\
	(hi) ^= ((b) & 0xF0F0) >> 4 & -((a) >> 12 & 1);\
	(hi) ^= ((b) & 0xE0E0) >> 5 & -((a) >> 11 & 1);\
	(hi) ^= ((b) & 0xC0C0) >> 6 & -((a) >> 10 & 1);\
	(hi) ^= ((b) & 0x8080) >> 7 & -((a) >> 9 & 1);\

#elif (B_PER_W == 32)

#define _MUL_MUL_S2(lo, hi, t, b)\
	(lo) = (t)[(b) >> 30] << 2 ^ (t)[(b) >> 28 & 3];\
	(hi) = (lo) >> 28;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 26 & 3] << 2 ^ (t)[(b) >> 24 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 28;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 22 & 3] << 2 ^ (t)[(b) >> 20 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 28;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 18 & 3] << 2 ^ (t)[(b) >> 16 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 28;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 14 & 3] << 2 ^ (t)[(b) >> 12 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 28;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 10 & 3] << 2 ^ (t)[(b) >> 8 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 28;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 6 & 3] << 2 ^ (t)[(b) >> 4 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 28;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 2 & 3] << 2 ^ (t)[(b) & 3];\

#define _MUL_MUL_S3(lo, hi, t, b)\
   (lo) = (t)[(b) >> 30];\
   (hi) = (lo) >> 26;\
   (lo) = (lo) << 6 ^ (t)[(b) >> 27 & 7] << 3 ^ (t)[(b) >> 24 & 7];\
   (hi) = (hi) << 6 ^ (lo) >> 26;\
   (lo) = (lo) << 6 ^ (t)[(b) >> 21 & 7] << 3 ^ (t)[(b) >> 18 & 7];\
   (hi) = (hi) << 6 ^ (lo) >> 26;\
   (lo) = (lo) << 6 ^ (t)[(b) >> 15 & 7] << 3 ^ (t)[(b) >> 12 & 7];\
   (hi) = (hi) << 6 ^ (lo) >> 26;\
   (lo) = (lo) << 6 ^ (t)[(b) >> 9 & 7] << 3 ^ (t)[(b) >> 6 & 7];\
   (hi) = (hi) << 6 ^ (lo) >> 26;\
   (lo) = (lo) << 6 ^ (t)[(b) >> 3 & 7] << 3 ^ (t)[(b) & 7];\

#define _MUL_MUL_S4(lo, hi, t, b)\
	(lo) = (t)[(b) >> 28] << 4 ^ (t)[(b) >> 24 & 15];\
	(hi) = (lo) >> 24;\
	(lo) = (lo) << 8 ^ (t)[(b) >> 20 & 15] << 4 ^ (t)[(b) >> 16 & 15];\
	(hi) = (hi) << 8 ^ (lo) >> 24;\
	(lo) = (lo) << 8 ^ (t)[(b) >> 12 & 15] << 4 ^ (t)[(b) >> 8 & 15];\
	(hi) = (hi) << 8 ^ (lo) >> 24;\
	(lo) = (lo) << 8 ^ (t)[(b) >> 4 & 15] << 4 ^ (t)[(b) & 15];\

#define _MUL_REPAIR_S2(hi, a, b)\
	(hi) ^= ((b) & 0xEEEEEEEE) >> 1 & -((a) >> 31);\
	(hi) ^= ((b) & 0xCCCCCCCC) >> 2 & -((a) >> 30 & 1);\
	(hi) ^= ((b) & 0x88888888) >> 3 & -((a) >> 29 & 1);\

#define _MUL_REPAIR_S3(hi, a, b)\
	(hi) ^= ((b) & 0xBEFBEFBE) >> 1 & -((a) >> 31);\
	(hi) ^= ((b) & 0x3CF3CF3C) >> 2 & -((a) >> 30 & 1);\
	(hi) ^= ((b) & 0x38E38E38) >> 3 & -((a) >> 29 & 1);\
	(hi) ^= ((b) & 0x30C30C30) >> 4 & -((a) >> 28 & 1);\
	(hi) ^= ((b) & 0x20820820) >> 5 & -((a) >> 27 & 1);\

#define _MUL_REPAIR_S4(hi, a, b)\
	(hi) ^= ((b) & 0xFEFEFEFE) >> 1 & -((a) >> 31);\
	(hi) ^= ((b) & 0xFCFCFCFC) >> 2 & -((a) >> 30 & 1);\
	(hi) ^= ((b) & 0xF8F8F8F8) >> 3 & -((a) >> 29 & 1);\
	(hi) ^= ((b) & 0xF0F0F0F0) >> 4 & -((a) >> 28 & 1);\
	(hi) ^= ((b) & 0xE0E0E0E0) >> 5 & -((a) >> 27 & 1);\
	(hi) ^= ((b) & 0xC0C0C0C0) >> 6 & -((a) >> 26 & 1);\
	(hi) ^= ((b) & 0x80808080) >> 7 & -((a) >> 25 & 1);\

#elif (B_PER_W == 64)

#define _MUL_MUL_S2(lo, hi, t, b)\
	(lo) = (t)[(b) >> 62] << 2 ^ (t)[(b) >> 60 & 3];\
	(hi) = (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 58 & 3] << 2 ^ (t)[(b) >> 56 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 54 & 3] << 2 ^ (t)[(b) >> 52 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 50 & 3] << 2 ^ (t)[(b) >> 48 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 46 & 3] << 2 ^ (t)[(b) >> 44 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 42 & 3] << 2 ^ (t)[(b) >> 40 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 38 & 3] << 2 ^ (t)[(b) >> 36 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 34 & 3] << 2 ^ (t)[(b) >> 32 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 30 & 3] << 2 ^ (t)[(b) >> 28 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 26 & 3] << 2 ^ (t)[(b) >> 24 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 22 & 3] << 2 ^ (t)[(b) >> 20 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 18 & 3] << 2 ^ (t)[(b) >> 16 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 14 & 3] << 2 ^ (t)[(b) >> 12 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 10 & 3] << 2 ^ (t)[(b) >> 8 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 6 & 3] << 2 ^ (t)[(b) >> 4 & 3];\
	(hi) = (hi) << 4 ^ (lo) >> 60;\
	(lo) = (lo) << 4 ^ (t)[(b) >> 2 & 3] << 2 ^ (t)[(b) & 3];\

#define _MUL_MUL_S3(lo, hi, t, b)\
	(lo) = (t)[(b) >> 63] << 3 ^ (t)[(b) >> 60 & 7];\
	(hi) = (lo) >> 58;\
	(lo) = (lo) << 6 ^ (t)[(b) >> 57 & 7] << 3 ^ (t)[(b) >> 54 & 7];\
	(hi) = (hi) << 6 ^ (lo) >> 58;\
	(lo) = (lo << 6) ^ (t)[(b) >> 51 & 7] << 3 ^ (t)[(b) >> 48 & 7];\
	(hi) = (hi) << 6 ^ (lo) >> 58;\
	(lo) = (lo) << 6 ^ (t)[(b) >> 45 & 7] << 3 ^ (t)[(b) >> 42 & 7];\
	(hi) = (hi) << 6 ^ (lo) >> 58;\
	(lo) = (lo) << 6 ^ (t)[(b) >> 39 & 7] << 3 ^ (t)[(b) >> 36 & 7];\
	(hi) = (hi) << 6 ^ (lo) >> 58;\
	(lo) = (lo) << 6 ^ (t)[(b) >> 33 & 7] << 3 ^ (t)[(b) >> 30 & 7];\
	(hi) = (hi) << 6 ^ (lo) >> 58;\
	(lo) = (lo) << 6 ^ (t)[(b) >> 27 & 7] << 3 ^ (t)[(b) >> 24 & 7];\
	(hi) = (hi) << 6 ^ (lo) >> 58;\
	(lo) = (lo) << 6 ^ (t)[(b) >> 21 & 7] << 3 ^ (t)[(b) >> 18 & 7];\
	(hi) = (hi) << 6 ^ (lo) >> 58;\
	(lo) = (lo) << 6 ^ (t)[(b) >> 15 & 7] << 3 ^ (t)[(b) >> 12 & 7];\
	(hi) = (hi) << 6 ^ (lo) >> 58;\
	(lo) = (lo) << 6 ^ (t)[(b) >> 9 & 7] << 3 ^ (t)[(b) >> 6 & 7];\
	(hi) = (hi) << 6 ^ (lo) >> 58;\
	(lo) = (lo) << 6 ^ (t)[(b) >> 3 & 7] << 3 ^ (t)[(b) & 7];\

#define _MUL_MUL_S4(lo, hi, t, b)\
	(lo) = (t)[(b) >> 60] << 4 ^ (t)[(b) >> 56 & 15];\
	(hi) = (lo) >> 56;\
	(lo) = (lo) << 8 ^ (t)[(b) >> 52 & 15] << 4 ^ (t)[(b) >> 48 & 15];\
	(hi) = (hi) << 8 ^ (lo) >> 56;\
	(lo) = (lo) << 8 ^ (t)[(b) >> 44 & 15] << 4 ^ (t)[(b) >> 40 & 15];\
	(hi) = (hi) << 8 ^ (lo) >> 56;\
	(lo) = (lo) << 8 ^ (t)[(b) >> 36 & 15] << 4 ^ (t)[(b) >> 32 & 15];\
	(hi) = (hi) << 8 ^ (lo) >> 56;\
	(lo) = (lo) << 8 ^ (t)[(b) >> 28 & 15] << 4 ^ (t)[(b) >> 24 & 15];\
	(hi) = (hi) << 8 ^ (lo) >> 56;\
	(lo) = (lo) << 8 ^ (t)[(b) >> 20 & 15] << 4 ^ (t)[(b) >> 16 & 15];\
	(hi) = (hi) << 8 ^ (lo) >> 56;\
	(lo) = (lo) << 8 ^ (t)[(b) >> 12 & 15] << 4 ^ (t)[(b) >> 8 & 15];\
	(hi) = (hi) << 8 ^ (lo) >> 56;\
	(lo) = (lo) << 8 ^ (t)[(b) >> 4 & 15] << 4 ^ (t)[(b) & 15];\

#define _MUL_REPAIR_S2(hi, a, b)\
	(hi) ^= ((b) & 0xEEEEEEEEEEEEEEEE) >> 1 & -((a) >> 63);\
	(hi) ^= ((b) & 0xCCCCCCCCCCCCCCCC) >> 2 & -((a) >> 62 & 1);\
	(hi) ^= ((b) & 0x8888888888888888) >> 3 & -((a) >> 61 & 1);\

#define _MUL_REPAIR_S3(hi, a, b)\
	(hi) ^= ((b) & 0xEFBEFBEFBEFBEFBE) >> 1 & -((a) >> 63);\
	(hi) ^= ((b) & 0xCF3CF3CF3CF3CF3C) >> 2 & -((a) >> 62 & 1);\
	(hi) ^= ((b) & 0x8E38E38E38E38E38) >> 3 & -((a) >> 61 & 1);\
	(hi) ^= ((b) & 0x0C30C30C30C30C30) >> 4 & -((a) >> 60 & 1);\
	(hi) ^= ((b) & 0x0820820820820820) >> 5 & -((a) >> 59 & 1);\

#define _MUL_REPAIR_S4(hi, a, b)\
	(hi) ^= ((b) & 0xFEFEFEFEFEFEFEFE) >> 1 & -((a) >> 63);\
	(hi) ^= ((b) & 0xFCFCFCFCFCFCFCFC) >> 2 & -((a) >> 62 & 1);\
	(hi) ^= ((b) & 0xF8F8F8F8F8F8F8F8) >> 3 & -((a) >> 61 & 1);\
	(hi) ^= ((b) & 0xF0F0F0F0F0F0F0F0) >> 4 & -((a) >> 60 & 1);\
	(hi) ^= ((b) & 0xE0E0E0E0E0E0E0E0) >> 5 & -((a) >> 59 & 1);\
	(hi) ^= ((b) & 0xC0C0C0C0C0C0C0C0) >> 6 & -((a) >> 58 & 1);\
	(hi) ^= ((b) & 0x8080808080808080) >> 7 & -((a) >> 57 & 1);\

#else
	#error "Unsupported word size"
#endif // B_PER_W

#define _MUL1(c, a, b, t)\
	_MUL_PRE_S4(t, a);\
	_MUL_MUL_S4((c)[0], (c)[1], t, b);\
	_MUL_REPAIR_S4((c)[1], a, b);\

/*
*******************************************************************************
Описание базовых функций умножения
*******************************************************************************
*/

static void ppMul1(word c[2], const word a[1], const word b[1], void* stack);
static void ppMul2(word c[4], const word a[2], const word b[2], void* stack);
static void ppMul3(word c[6], const word a[3], const word b[3], void* stack);
static void ppMul4(word c[8], const word a[4], const word b[4], void* stack);
static void ppMul5(word c[10], const word a[5], const word b[5], 
	void* stack);
static void ppMul6(word c[12], const word a[6], const word b[6],
	void* stack);
static void ppMul7(word c[14], const word a[7], const word b[7],
	void* stack);
static void ppMul8(word c[16], const word a[8], const word b[8], 
	void* stack);
static void ppMul9(word c[18], const word a[9], const word b[9], 
	void* stack);

/*
*******************************************************************************
Умножение слов
*******************************************************************************
*/

static void ppMul1(word c[2], const word a[1], const word b[1], void* stack)
{
	_MUL1(c, a[0], b[0], (word*)stack);
}

static size_t ppMul1_deep()
{
	return O_OF_W(16);
}

/*
*******************************************************************************
Умножение Карацубы (Kara2_n):
	(a1 X + a0)(b1 X + b0) =
		a1 b1 X^2 + [a1 b1 + (a1 + a0)(b1 + b0) + a0 b0] X + a0 b0,
где
	a0 = a[0..n-1], a1 = a[n..2n-1]
	b0 = b[0..n-1], b1 = b[n..2n-1]

Схема вычислений (n > 1):
	c1 || c0 <- a0 b0
	c3 || c2 <- a1 b1
	t0       <- a0 + a1
	t1       <- b0 + b1
	t2       <- c1 + c2
	c2 || c1 <- t0 t1
	c1       <- c1 + c0 + t2
	c2       <- c2 + c3 + t2

Схема вычислений (n == 1):
	c1 || c0 <- a0 b0
	c3 || c2 <- a1 b1
	t0       <- c1 + c2
	c2 || c1 <- (a0 + a1)(b0 + b1)
	c1       <- c1 + c0 + t0
	c2       <- c2 + c3 + t0

Глубина стека (в машинных словах) при обработке многочленов из 1 слова:
	deep(Kara2_1) = deep(_MUL1) + 1

Глубина стека при обработке многочленов из 2n слов:
	deep(Kara2_2n) <= deep(Kara2_n) + 3n

Если n -- степень 2, для подчиненных умножений используется Kara, то
	deep(Kara2_2^s) <= deep(_MUL1) + 1 + 3 * 2 + 3 * 2^2 +...+ 3 * 2^{s-1}
					 = deep(_MUL1) + 1 + 3 (2^s - 2)
*******************************************************************************
*/

static void ppMul2(word c[4], const word a[2], const word b[2], void* stack)
{
	word* t = (word*)stack;
	ASSERT(wwIsDisjoint2(a, 2, c, 4));
	ASSERT(wwIsDisjoint2(b, 2, c, 4));
	// c1 || c0 <- a0 b0
	_MUL1(c, a[0], b[0], t);
	// c3 || c2 <- a1 b1
	_MUL1(c + 2, a[1], b[1], t);
	// t0 <- c1 + c2
	t[0] = c[1] ^ c[2];
	// с2 || с1 <- (a0 + a1)(b0 + b1)
	_MUL1(c + 1, a[0] ^ a[1], b[0] ^ b[1], t + 1);
	// c1 <- c1 + c0 + w2
	c[1] ^= c[0] ^ t[0];
	// c2 <- c2 + c3 + w2
	c[2] ^= c[3] ^ t[0];
}

static size_t ppMul2_deep()
{
	return O_OF_W(1) + ppMul1_deep();
}

static void ppMul4(word c[8], const word a[4], const word b[4], void* stack)
{
	word* t = (word*)stack;
	ASSERT(wwIsDisjoint2(a, 4, c, 8));
	ASSERT(wwIsDisjoint2(b, 4, c, 8));
	// c1 || c0 <- a0 b0
	ppMul2(c, a, b, t);
	// c3 || c2 <- a1 b1
	ppMul2(c + 4, a + 2, b + 2, t);
	// t0 <- a0 + a1
	t[0] = a[0] ^ a[2];
	t[1] = a[1] ^ a[3];
	// t1 <- b0 + b1
	t[2] = b[0] ^ b[2];
	t[3] = b[1] ^ b[3];
	// t2 <- c1 + c2
	t[4] = c[2] ^ c[4];
	t[5] = c[3] ^ c[5];
	// c2 || c1 <- t0 t1
	ppMul2(c + 2, t, t + 2, t + 6);
	// c1 <- c1 + c0 + w2
	c[2] ^= c[0] ^ t[4];
	c[3] ^= c[1] ^ t[5];
	// c2 <- c2 + c3 + w2
	c[4] ^= c[6] ^ t[4];
	c[5] ^= c[7] ^ t[5];
}

static size_t ppMul4_deep()
{
	return O_OF_W(6) + ppMul2_deep();
}

static void ppMul6(word c[12], const word a[6], const word b[6], void* stack)
{
	word* t = (word*)stack;
	ASSERT(wwIsDisjoint2(a, 6, c, 12));
	ASSERT(wwIsDisjoint2(b, 6, c, 12));
	// c1 || c0 <- a0 b0
	ppMul3(c, a, b, t);
	// c3 || c2 <- a1 b1
	ppMul3(c + 6, a + 3, b + 3, t);
	// t0 <- a0 + a1
	t[0] = a[0] ^ a[3];
	t[1] = a[1] ^ a[4];
	t[2] = a[2] ^ a[5];
	// t1 <- b0 + b1
	t[3] = b[0] ^ b[3];
	t[4] = b[1] ^ b[4];
	t[5] = b[2] ^ b[5];
	// t2 <- c1 + c2
	t[6] = c[3] ^ c[6];
	t[7] = c[4] ^ c[7];
	t[8] = c[5] ^ c[8];
	// c2 || c1 <- t0 t1
	ppMul3(c + 3, t, t + 3, t + 9);
	// c1 <- c1 + c0 + w2
	c[3] ^= c[0] ^ t[6];
	c[4] ^= c[1] ^ t[7];
	c[5] ^= c[2] ^ t[8];
	// c2 <- c2 + c3 + w2
	c[6] ^= c[9] ^ t[6];
	c[7] ^= c[10] ^ t[7];
	c[8] ^= c[11] ^ t[8];
}

static size_t ppMul3_deep();

static size_t ppMul6_deep()
{
	return O_OF_W(9) + ppMul3_deep();
}

static void ppMul8(word c[16], const word a[8], const word b[8], void* stack)
{
	word* t = (word*)stack;
	ASSERT(wwIsDisjoint2(a, 8, c, 16));
	ASSERT(wwIsDisjoint2(b, 8, c, 16));
	// c1 || c0 <- a0 b0
	ppMul4(c, a, b, t);
	// c3 || c2 <- a1 b1
	ppMul4(c + 8, a + 4, b + 4, t);
	// t0 <- a0 + a1
	t[0] = a[0] ^ a[4];
	t[1] = a[1] ^ a[5];
	t[2] = a[2] ^ a[6];
	t[3] = a[3] ^ a[7];
	// t1 <- b0 + b1
	t[4] = b[0] ^ b[4];
	t[5] = b[1] ^ b[5];
	t[6] = b[2] ^ b[6];
	t[7] = b[3] ^ b[7];
	// t2 <- c1 + c2
	t[8] = c[4] ^ c[8];
	t[9] = c[5] ^ c[9];
	t[10] = c[6] ^ c[10];
	t[11] = c[7] ^ c[11];
	// c2 || c1 <- w0 w1
	ppMul4(c + 4, t, t + 4, t + 12);
	// c1 <- c1 + c0 + w2
	c[4] ^= c[0] ^ t[8];
	c[5] ^= c[1] ^ t[9];
	c[6] ^= c[2] ^ t[10];
	c[7] ^= c[3] ^ t[11];
	// c2 <- c2 + c3 + w2
	c[8] ^= c[12] ^ t[8];
	c[9] ^= c[13] ^ t[9];
	c[10] ^= c[14] ^ t[10];
	c[11] ^= c[15] ^ t[11];
}

static size_t ppMul8_deep()
{
	return O_OF_W(12) + ppMul4_deep();
}

/*
*******************************************************************************
Усеченное умножение Карацубы (Kara2_n):
	(a1 X + a0)(b1 X + b0) =
		a1 b1 X^2 + [a1 b1 + (a1 + a0)(b1 + b0) + a0 b0] X + a0 b0,
где
	a0 = a[0..n-1], a1 = a[n..n + m -1]
	b0 = b[0..n-1], b1 = b[n..n + m -1], m < n
*******************************************************************************
*/

static void ppMul5(word c[10], const word a[5], const word b[5], void* stack)
{
	word* t = (word*)stack;
	ASSERT(wwIsDisjoint2(a, 5, c, 10));
	ASSERT(wwIsDisjoint2(b, 5, c, 10));
	// c1 || c0 <- a0 b0
	ppMul3(c, a, b, t);
	// c3 || c2 <- a1 b1
	ppMul2(c + 6, a + 3, b + 3, t);
	// t0 <- a0 + a1
	t[0] = a[0] ^ a[3];
	t[1] = a[1] ^ a[4];
	t[2] = a[2];
	// t1 <- b0 + b1
	t[3] = b[0] ^ b[3];
	t[4] = b[1] ^ b[4];
	t[5] = b[2];
	// t2 <- c1 + c2
	t[6] = c[3] ^ c[6];
	t[7] = c[4] ^ c[7];
	t[8] = c[5] ^ c[8];
	// c2 || c1 <- t0 t1
	ppMul3(c + 3, t, t + 3, t + 9);
	// c1 <- c1 + c0 + t2
	c[3] ^= c[0] ^ t[6];
	c[4] ^= c[1] ^ t[7];
	c[5] ^= c[2] ^ t[8];
	// c2 <- c2 + c3 + t2
	c[6] ^= c[9] ^ t[6];
	c[7] ^= t[7];
	c[8] ^= t[8];
}

static size_t ppMul5_deep()
{
	return O_OF_W(9) + ppMul3_deep();
}

static void ppMul7(word c[14], const word a[7], const word b[7], void* stack)
{
	word* t = (word*)stack;
	ASSERT(wwIsDisjoint2(a, 7, c, 14));
	ASSERT(wwIsDisjoint2(b, 7, c, 14));
	// c1 || c0 <- a0 b0
	ppMul4(c, a, b, t);
	// c3 || c2 <- a1 b1
	ppMul3(c + 8, a + 4, b + 4, t);
	// t0 <- a0 + a1
	t[0] = a[0] ^ a[4];
	t[1] = a[1] ^ a[5];
	t[2] = a[2] ^ a[6];
	t[3] = a[3];
	// t1 <- b0 + b1
	t[4] = b[0] ^ b[4];
	t[5] = b[1] ^ b[5];
	t[6] = b[2] ^ b[6];
	t[7] = b[3];
	// t2 <- c1 + c2
	t[8] = c[4] ^ c[8];
	t[9] = c[5] ^ c[9];
	t[10] = c[6] ^ c[10];
	t[11] = c[7] ^ c[11];
	// c2 || c1 <- t0 t1
	ppMul4(c + 4, t, t + 4, t + 12);
	// c1 <- c1 + c0 + t2
	c[4] ^= c[0] ^ t[8];
	c[5] ^= c[1] ^ t[9];
	c[6] ^= c[2] ^ t[10];
	c[7] ^= c[3] ^ t[11];
	// c2 <- c2 + c3 + t2
	c[8] ^= c[12] ^ t[8];
	c[9] ^= c[13] ^ t[9];
	c[10] ^= t[10];
	c[11] ^= t[11];
}

static size_t ppMul7_deep()
{
	return O_OF_W(12) + ppMul4_deep();
}

/*
*******************************************************************************
Модифицированное умножение Карацубы (Kara3_n):
	(a2 X^2 + a1 X + a0)(b2 x^2 + b1 X + b0) =
		d2 X^4 + (d12 + d1 + d2)x^3 + (d02 + d0 + d1 + d2)x^2 +
		(d01 + d0 + d1)x + d0,
где
	a0 = a[0..2n-1], a1 = a[n..2n-1], a2 = a[2n..3n-1]
	b0 = b[0..2n-1], b1 = b[n..2n-1], b3 = b[2n..3n-1]
	d0 = a0 b0, d1 = a1 b1, d2 = a2 b2,
	d01 = (a0 + a1)(b0 + b1),
	d02 = (a0 + a2)(b0 + b2),
	d12 = (a1 + a2)(b1 + b2)
[Weimerskirch A., Paar C.
 Generalizations of the Karatsuba Algorithm for Efficient Implementation, 2006,
 http://weimerskirch.org/papers/Weimerskirch_Karatsuba.pdf]

Схема вычислений (6M + 13A):
	c1 || c0 <- a0 b0
	c3 || c2 <- a1 b1
	c5 || c4 <- a2 b2
	// должно получиться расположение
	// (c5)||(c3 + c4 + c5)||(c1 +...+ c5)||(c0 +...+ c4)||(c0 + c1 + c2)||(c0)
	c1       <- c1 + c0 + c2
	c2       <- c1 + c3 + c4
	c3       <- c2 + c0 + c5
	c4       <- c3 + c0 + c1
	t2       <- a0 + a1
	t3       <- b0 + b1
	t4       <- a0 + a2
	t5       <- b0 + b2
	t1 || t0 <- t2 t3
	c1       <- c1 + t0
	c2       <- c2 + t1
	t1 || t0 <- t4 t5
	c2       <- c2 + t0
	c3       <- c3 + t1
	t4       <- t4 + t2
	t5       <- t5 + t3
	t1 || t0 <- t4 t5
	c3       <- c3 + t0
	c4       <- c4 + t1

Глубина стека при обработке многочленов из 1 слова:
	deep(Kara3_1) = deep(ppMul32) = 16

Глубина стека при обработке многочленов из 3n слов:
	deep(Kara3_3n) <= deep(Mul_n) + 6n

Если n -- степень 3, для подчиненных умножений используется Kara3, то
	deep(Kara3_3^s)	<= 16 + 6 + 6 * 3 + 6 * 3^2 + ... + 6 * 3^{s-1}
					= 16 + 6(3^s - 1)
*******************************************************************************
*/

static void ppMul3(word c[6], const word a[3], const word b[3], void* stack)
{
	word* t = (word*)stack;
	ASSERT(wwIsDisjoint2(a, 3, c, 6));
	ASSERT(wwIsDisjoint2(b, 3, c, 6));
	// c1 || c0 <- a0 b0
	_MUL1(c, a[0], b[0], t);
	// c3 || c2 <- a1 b1
	_MUL1(c + 2, a[1], b[1], t);
	// c5 || c4 <- a2 b2
	_MUL1(c + 4, a[2], b[2], t);
	// c1 <- c1 + c0 + c2
	c[1] ^= c[0] ^ c[2];
	// c2 <- c1 + c3 + c4
	c[2] = c[1] ^ c[3] ^ c[4];
	// c3 <- c2 + c0 + c5
	c[3] = c[2] ^ c[0] ^ c[5];
	// c4 <- c3 + c0 + c1
	c[4] = c[3] ^ c[0] ^ c[1];
	// t1 || t0 <- (a0 + a1)(b0 + b1)
	_MUL1(t, a[0] ^ a[1], b[0] ^ b[1], t + 2);
	// c1 <- c1 + t0
	c[1] ^= t[0];
	// c2 <- c2 + t1
	c[2] ^= t[1];
	// t1 || t0 <- (a0 + a2)(b0 + b2)
	_MUL1(t, a[0] ^ a[2], b[0] ^ b[2], t + 2);
	// c2 <- c2 + t0
	c[2] ^= t[0];
	// c3 <- c3 + t1
	c[3] ^= t[1];
	// t1 || t0 <- (a1 + a2)(b1 + b2)
	_MUL1(t, a[1] ^ a[2], b[1] ^ b[2], t + 2);
	// c3 <- c3 + t0
	c[3] ^= t[0];
	// c4 <- c4 + t1
	c[4] ^= t[1];
}

static size_t ppMul3_deep()
{
	return O_OF_W(2 + 16);
}

static void ppMul9(word c[18], const word a[9], const word b[9], void* stack)
{
	word* t = (word*)stack;
	ASSERT(wwIsDisjoint2(a, 9, c, 18));
	ASSERT(wwIsDisjoint2(b, 9, c, 18));
	// c1 || c0 <- a0 b0
	ppMul3(c, a, b, t);
	// c3 || c2 <- a1 b1
	ppMul3(c + 6, a + 3, b + 3, t);
	// c5 || c4 <- a2 b2
	ppMul3(c + 12, a + 6, b + 6, t);
	// c1 <- c1 + c0 + c2
	c[3] ^= c[0] ^ c[6];
	c[4] ^= c[1] ^ c[7];
	c[5] ^= c[2] ^ c[8];
	// c2 <- c1 + c3 + c4
	c[6] = c[3] ^ c[9] ^ c[12];
	c[7] = c[4] ^ c[10] ^ c[13];
	c[8] = c[5] ^ c[11] ^ c[14];
	// c3 <- c2 + c0 + c5
	c[9] = c[6] ^ c[0] ^ c[15];
	c[10] = c[7] ^ c[1] ^ c[16];
	c[11] = c[8] ^ c[2] ^ c[17];
	// c4 <- c3 + c0 + c1
	c[12] = c[9] ^ c[0] ^ c[3];
	c[13] = c[10] ^ c[1] ^ c[4];
	c[14] = c[11] ^ c[2] ^ c[5];
	// t2 <- a0 + a1
	t[6] = a[0] ^ a[3];
	t[7] = a[1] ^ a[4];
	t[8] = a[2] ^ a[5];
	// t3 <- b0 + b1
	t[9] = b[0] ^ b[3];
	t[10] = b[1] ^ b[4];
	t[11] = b[2] ^ b[5];
	// t4 <- a0 + a2
	t[12] = a[0] ^ a[6];
	t[13] = a[1] ^ a[7];
	t[14] = a[2] ^ a[8];
	// t5 <- b0 + b2
	t[15] = b[0] ^ b[6];
	t[16] = b[1] ^ b[7];
	t[17] = b[2] ^ b[8];
	// t1 || t0 <- t2 t3
	ppMul3(t, t + 6, t + 9, t + 18);
	// c1 <- c1 + t0
	c[3] ^= t[0];
	c[4] ^= t[1];
	c[5] ^= t[2];
	// c2 <- c2 + t1
	c[6] ^= t[3];
	c[7] ^= t[4];
	c[8] ^= t[5];
	// t1 || t0 <- t4 t5
	ppMul3(t, t + 12, t + 15, t + 18);
	// c2 <- c2 + t0
	c[6] ^= t[0];
	c[7] ^= t[1];
	c[8] ^= t[2];
	// c3 <- c3 + t1
	c[9] ^= t[3];
	c[10] ^= t[4];
	c[11] ^= t[5];
	// t4 <- t4 + t2
	t[12] ^= t[6];
	t[13] ^= t[7];
	t[14] ^= t[8];
	// t5 <- t5 + t3
	t[15] ^= t[9];
	t[16] ^= t[10];
	t[17] ^= t[11];
	// t1 || t0 <- t4 t5
	ppMul3(t, t + 12, t + 15, t + 18);
	// c3 <- c3 + t0
	c[9] ^= t[0];
	c[10] ^= t[1];
	c[11] ^= t[2];
	// c4 <- c4 + t1
	c[12] ^= t[3];
	c[13] ^= t[4];
	c[14] ^= t[5];
}

static size_t ppMul9_deep()
{
	return O_OF_W(18) + ppMul3_deep();
}

/*
*******************************************************************************
Умножение на слово
*******************************************************************************
*/

word ppMulW(word b[], const word a[], size_t n, register word w, 
	void* stack)
{
	register word carry = 0;
	size_t i;
	word* t = (word*)stack;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	_MUL_PRE_S4(t, w);
	for (i = 0; i < n; ++i)
	{
		_MUL_MUL_S4(t[16], t[17], t, a[i]);
		_MUL_REPAIR_S4(t[17], w, a[i]);
		b[i] = carry ^ t[16];
		carry = t[17];
	}
	w = 0;
	return carry;
}

size_t ppMulW_deep(size_t n)
{
	return O_OF_W(16 + 2);
}

word ppAddMulW(word b[], const word a[], size_t n, register word w, 
	void* stack)
{
	register word carry = 0;
	size_t i;
	word* t = (word*)stack;
	ASSERT(wwIsSameOrDisjoint(a, b, n));
	_MUL_PRE_S4(t, w);
	for (i = 0; i < n; ++i)
	{
		_MUL_MUL_S4(t[16], t[17], t, a[i]);
		_MUL_REPAIR_S4(t[17], w, a[i]);
		b[i] ^= carry ^ t[16];
		carry = t[17];
	}
	w = 0;
	return carry;
}

size_t ppAddMulW_deep(size_t n)
{
	return O_OF_W(16 + 2);
}

/*
*******************************************************************************
Умножение в общем случае

В массиве _mul_funcs задаются базовые функции умножения многочленов малой
одинаковой длины.

Функция _ppMulEq() реализует умножение многочленов одинаковой длины.
Используются функции из таблицы _mul_funcs либо алгоритм Карацубы
(возможно усеченный).

deep1(_ppMulEq, n) =
	max(deep1(_ppMulEq, m), deep1(_ppMulEq, n - m))	+ 4 * m,
где m = n / 2 при четном n и m = (n + 1) / 2 при нечетном m.
*******************************************************************************
*/

typedef void (*_pp_mul_proc)(word*, const word*, const word*, void*);

static const _pp_mul_proc _mul_procs[] =
{
	0,
	ppMul1, ppMul2, ppMul3, ppMul4, ppMul5, ppMul6, ppMul7,
	ppMul8, ppMul9,
};

static void ppMulEq(word c[], const word a[], const word b[], size_t n,
	void* stack)
{
	ASSERT(wwIsDisjoint2(a, n, c, 2 * n));
	ASSERT(wwIsDisjoint2(b, n, c, 2 * n));
	// умножение многочленов малой длины
	if (n < COUNT_OF(_mul_procs))
		_mul_procs[n](c, a, b, stack);
	// усеченный алгоритм Карацубы, n --- четное
	else if ((n & 1) == 0)
	{
		word* t = (word*)stack;
		size_t m = n / 2, i;
		// c1 || c0 <- a0 b0
		ppMulEq(c, a, b, m, t);
		// c3 || c2 <- a1 b1
		ppMulEq(c + 2 * m, a + m, b + m, m, t);
		// t0 <- a0 + a1, t1 <- b0 + b1, t2 <- c1 + c2
		for (i = 0; i < m; ++i)
			t[i] = a[i] ^ a[m + i],
			t[m + i] = b[i] ^ b[m + i],
			t[2 * m + i] = c[m + i] ^ c[2 * m + i];
		// c2 || c1 <- t0 t1
		ppMulEq(c + m, t, t + m, m, t + 3 * m);
		// c1 <- c1 + c0 + t2, c2 <- c2 + c3 + t2
		for (i = 0; i < m; ++i)
			c[m + i] ^= c[i] ^ t[2 * m + i],
			c[2 * m + i] ^= c[3 * m + i] ^ t[2 * m + i];
	}
	// усеченный алгоритм Карацубы, n --- нечетное
	else
	{
		word* t = (word*)stack;
		size_t m = (n + 1) / 2, i;
		// c1 || c0 <- a0 b0
		ppMulEq(c, a, b, m, t);
		// c3 || c2 <- a1 b1
		ppMulEq(c + 2 * m, a + m, b + m, n - m, t);
		// t0 <- a0 + a1, t1 <- b0 + b1, t2 <- c1 + c2
		for (i = 0; i + 1 < m; ++i)
			t[i] = a[i] ^ a[m + i],
			t[m + i] = b[i] ^ b[m + i],
			t[2 * m + i] = c[m + i] ^ c[2 * m + i];
		t[i] = a[i];
		t[m + i] = b[i];
		t[2 * m + i] = c[m + i] ^ c[2 * m + i];
		// c2 || c1 <- t0 t1
		ppMulEq(c + m, t, t + m, m, t + 3 * m);
		// c1 <- c1 + c0 + t2, c2 <- c2 + c3 + t2
		for (i = 0; i + 2 < m; ++i)
			c[m + i] ^= c[i] ^ t[2 * m + i],
			c[2 * m + i] ^= c[3 * m + i] ^ t[2 * m + i];
		c[m + i] ^= c[i] ^ t[2 * m + i];
		c[2 * m + i] ^= t[2 * m + i];
		++i;
		c[m + i] ^= c[i] ^ t[2 * m + i];
		c[2 * m + i] ^= t[2 * m + i];
	}
}

void ppMul(word c[], const word a[], size_t n, const word b[], size_t m,
	void* stack)
{
	ASSERT(wwIsDisjoint2(a, n, c, n + m));
	ASSERT(wwIsDisjoint2(b, m, c, n + m));
	// один из множителей пустой?
	if (n == 0 || m == 0)
	{
		wwSetZero(c, n + m);
		return;
	}
	// умножение многочленов одинаковой длины
	if (n == m)
		ppMulEq(c, a, b, n, stack);
	// длина a меньше длины b?
	else if (n < m)
		ppMul(c, b, m, a, n, stack);
	// длина a больше длины b
	else
	{
		size_t i;
		// умножаем части одинаковой длины
		ppMulEq(c, a, b, m, stack);
		// готовим старшую часть произведения
		wwSetZero(c + 2 * m, n - m);
		// умножаем старшие слова a на b
		for (i = m; i < n; ++i)
			c[i + m] ^= ppAddMulW(c + i, b, m, a[i], stack);
	}
}

/*
*******************************************************************************
Глубина стека функций ppMuln [профилировка 10.05.2012]:
	----------------
	n      deep
	----------------
	1		16
	2		17
	3		18
	4		23
	5		27
	6		27
	7		35
	8		35
	9		36
	----------------

Глубина стека d(n, m) функции ppMul рассчитывается по следующим правилам:
	d(n, m) = d(m, n)
	d(n, m) = max(d(n, n), d(1, 1) + 2), n < m
	d(n, n) = deep(ppMuln), 1 <= n < = 9 [см. пред. таблицу]
	d(n, n) = d(k, k) + 3k , 10 <= n, k = (n + 1)/2

Некоторые важные значения d(n, n) [профилировка 10.05.2012]:
	----------------
	 n       d(n, n)
	----------------
	 10         43
	 11, 12     45
	 13, 14     56
	 15, 16     59
	 17, 18     63
	----------------
*******************************************************************************
*/

size_t ppMul_deep(size_t n, size_t m)
{
	if (n == 0 || m == 0)
		return 0;
	if (n > m)
		return ppMul_deep(m, n);
	if (n < m)
		return utilMax(2,
			ppMul_deep(n, n),
			ppAddMulW_deep(n));
	if (n > 9)
	{
		size_t k = (n + 1) / 2;
		return ppMul_deep(k, k) + O_OF_W(3 * k);
	}
	switch (n)
	{
		case 1:
			return ppMul1_deep();
		case 2:
			return ppMul2_deep();
		case 3:
			return ppMul3_deep();
		case 4:
			return ppMul4_deep();
		case 5:
			return ppMul5_deep();
		case 6:
			return ppMul6_deep();
		case 7:
			return ppMul7_deep();
		case 8:
			return ppMul8_deep();
		case 9:
			return ppMul9_deep();
		default:
			ASSERT(0);
			return SIZE_MAX;
	}
}

/*
*******************************************************************************
Возведение в квадрат

Возведение в квадрат двоичной строки, представляющей многочлен, состоит
в прореживании строки нулями.
*******************************************************************************
*/

static const word _squares[256] =
{
	0, 1, 4, 5, 16, 17, 20, 21, 64, 65, 68, 69, 80, 81, 84, 85, 256, 257,
	260, 261, 272, 273, 276, 277, 320, 321, 324, 325, 336, 337, 340, 341,
	1024, 1025, 1028, 1029, 1040, 1041, 1044, 1045, 1088, 1089, 1092,
	1093, 1104, 1105, 1108, 1109, 1280, 1281, 1284, 1285, 1296, 1297,
	1300, 1301, 1344, 1345, 1348, 1349, 1360, 1361, 1364, 1365, 4096,
	4097, 4100, 4101, 4112, 4113, 4116, 4117, 4160, 4161, 4164, 4165,
	4176, 4177, 4180, 4181, 4352, 4353, 4356, 4357, 4368, 4369, 4372,
	4373, 4416, 4417, 4420, 4421, 4432, 4433, 4436, 4437, 5120, 5121,
	5124, 5125, 5136, 5137, 5140, 5141, 5184, 5185, 5188, 5189, 5200,
	5201, 5204, 5205, 5376, 5377, 5380, 5381, 5392, 5393, 5396, 5397,
	5440, 5441, 5444, 5445, 5456, 5457, 5460, 5461, 16384, 16385, 16388,
	16389, 16400, 16401, 16404, 16405, 16448, 16449, 16452, 16453, 16464,
	16465, 16468, 16469, 16640, 16641, 16644, 16645, 16656, 16657, 16660,
	16661, 16704, 16705, 16708, 16709, 16720, 16721, 16724, 16725, 17408,
	17409, 17412, 17413, 17424, 17425, 17428, 17429, 17472, 17473, 17476,
	17477, 17488, 17489, 17492, 17493, 17664, 17665, 17668, 17669, 17680,
	17681, 17684, 17685, 17728, 17729, 17732, 17733, 17744, 17745, 17748,
	17749, 20480, 20481, 20484, 20485, 20496, 20497, 20500, 20501, 20544,
	20545, 20548, 20549, 20560, 20561, 20564, 20565, 20736, 20737, 20740,
	20741, 20752, 20753, 20756, 20757, 20800, 20801, 20804, 20805, 20816,
	20817, 20820, 20821, 21504, 21505, 21508, 21509, 21520, 21521, 21524,
	21525, 21568, 21569, 21572, 21573, 21584, 21585, 21588, 21589, 21760,
	21761, 21764, 21765, 21776, 21777, 21780, 21781, 21824, 21825, 21828,
	21829, 21840, 21841, 21844, 21845,
};

#if (B_PER_W == 16)

#define _SQR_LO(a)\
	_squares[(a) & 255]

#define _SQR_HI(a)\
	_squares[(a) >> 8]

#elif (B_PER_W == 32)

#define _SQR_LO(a)\
	_squares[(a) & 255] | _squares[(a) >> 8 & 255] << 16

#define _SQR_HI(a)\
	_squares[(a) >> 16 & 255] | _squares[(a) >> 24] << 16

#elif (B_PER_W == 64)

#define _SQR_LO(a)\
	_squares[(a) & 255] | _squares[(a) >> 8 & 255] << 16 |\
	_squares[(a) >> 16 & 255] << 32 | _squares[(a) >> 24 & 255] << 48

#define _SQR_HI(a)\
	_squares[(a) >> 32 & 255] | _squares[(a) >> 40 & 255] << 16 |\
	_squares[(a) >> 48 & 255] << 32 | _squares[(a) >> 56] << 48

#else
	#error "Unsupported word size"
#endif

void ppSqr(word b[], const word a[], size_t n, void* stack)
{
	size_t i;
	ASSERT(wwIsDisjoint2(a, n, b, 2 * n));
	for (i = 0; i < n; ++i)
		b[i + i] = _SQR_LO(a[i]),
		b[i + i + 1] = _SQR_HI(a[i]);
}

size_t ppSqr_deep(size_t n)
{
	return 0;
}

/*
*******************************************************************************
Макросы деления многочленов-слов

Определяется частное q от деления многочлена из двух слов (hi, lo)
на многочлен (1, a):
	q <- (hi, lo) \div (1, a).
Здесь a -- явно заданное слово, 1 -- неявно дописываемый единичный разряд.

Частное q при делении всегда укладывается в одно слово и не зависит от lo.

Реализован оконный метод деления с длиной окна s = 4.

\todo Другие длины окон.

Макросы _DIV_PRE_SX рассчитывают таблицу частных:
	w[hi] <- (hi, lo) \div (1, a),	hi = 0, 1,..., 2^s - 1.
Расчет основан на наблюдении: если hi является d-разрядным, то
	w[1||hi] = (1 << d) ^ w[hi ^ старшие_d_битов_a].
*******************************************************************************
*/

#define _DIV_PRE_S2(w, a)\
	(w)[0] = 0;\
	(w)[1] = 1;\
	(w)[2] = 2 ^ (w)[0 ^ (a) >> (B_PER_W - 1)];\
	(w)[3] = 2 ^ (w)[1 ^ (a) >> (B_PER_W - 1)];\

#define _DIV_PRE_S3(w, a)\
	_DIV_PRE_S2(w, a)\
	(w)[4] = 4 ^ (w)[0 ^ (a) >> (B_PER_W - 2)];\
	(w)[5] = 4 ^ (w)[1 ^ (a) >> (B_PER_W - 2)];\
	(w)[6] = 4 ^ (w)[2 ^ (a) >> (B_PER_W - 2)];\
	(w)[7] = 4 ^ (w)[3 ^ (a) >> (B_PER_W - 2)];\

#define _DIV_PRE_S4(w, a)\
	_DIV_PRE_S3(w, a)\
	(w)[8] = 8 ^ (w)[0 ^ (a) >> (B_PER_W - 3)];\
	(w)[9] = 8 ^ (w)[1 ^ (a) >> (B_PER_W - 3)];\
	(w)[10] = 8 ^ (w)[2 ^ (a) >> (B_PER_W - 3)];\
	(w)[11] = 8 ^ (w)[3 ^ (a) >> (B_PER_W - 3)];\
	(w)[12] = 8 ^ (w)[4 ^ (a) >> (B_PER_W - 3)];\
	(w)[13] = 8 ^ (w)[5 ^ (a) >> (B_PER_W - 3)];\
	(w)[14] = 8 ^ (w)[6 ^ (a) >> (B_PER_W - 3)];\
	(w)[15] = 8 ^ (w)[7 ^ (a) >> (B_PER_W - 3)];\

#if (B_PER_W == 16)

#define _DIV_DIV_S4(hi, q, w1, w2)\
	(q) = (w1)[(hi) >> 12];\
	(hi) ^= (w2)[(q) & 15] >> 4;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 8 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 8;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 4 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 12;\
	(q) = (q) << 4 ^ (w1)[(hi) & 15];\

#elif (B_PER_W == 32)

#define _DIV_DIV_S4(hi, q, w1, w2)\
	(q) = (w1)[(hi) >> 28];\
	(hi) ^= (w2)[(q) & 15] >> 4;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 24 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 8;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 20 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 12;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 16 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 16;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 12 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 20;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 8 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 24;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 4 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 28;\
	(q) = (q) << 4 ^ (w1)[(hi) & 15];\

#elif (B_PER_W == 64)

#define _DIV_DIV_S4(hi, q, w1, w2)\
	(q) = (w1)[(hi) >> 60];\
	(hi) ^= (w2)[(q) & 15] >> 4;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 56 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 8;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 52 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 12;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 48 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 16;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 44 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 20;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 40 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 24;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 36 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 28;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 32 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 32;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 28 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 36;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 24 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 40;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 20 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 44;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 16 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 48;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 12 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 52;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 8 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 56;\
	(q) = (q) << 4 ^ (w1)[(hi) >> 4 & 15];\
	(hi) ^= (w2)[(q) & 15] >> 60;\
	(q) = (q) << 4 ^ (w1)[(hi) & 15];\

#else
	#error "Unsupported word size"
#endif // B_PER_W

/*
*******************************************************************************
Деление
*******************************************************************************
*/

void ppDiv(word q[], word r[], const word a[], size_t n, const word b[],
	size_t m, void* stack)
{
	register word dividentHi;
	register size_t shift;
	size_t i;
	// переменные в stack
	word* divident;		/* нормализованное делимое (n + 1 слово) */
	word* divisor;		/* нормализованный делитель (m слов) */
	word* w1;			/* таблица частных (16 слов) */
	word* w2;			/* таблица умножения (16 слов) */
	// pre
	ASSERT(n >= m);
	ASSERT(wwIsValid(a, n) && wwIsValid(b, m));
	ASSERT(m > 0 && b[m - 1] > 0);
	ASSERT(wwIsDisjoint2(q, n + 1 - m, r, m));
	ASSERT(a == r || wwIsDisjoint2(a, n, r, m));
	// a < b?
	if (wwCmp2(a, n, b, m) < 0)
	{
		// q <- 0, r <- a
		wwSetZero(q, n - m + 1);
		wwCopy(r, a, m);
		return;
	}
	// резервируем переменные в stack
	divident = (word*)stack;
	divisor = divident + n + 1;
	w1 = divisor + m;
	w2 = w1 + 16;
	stack = w2 + 16;
	// divident <- a
	wwCopy(divident, a, n);
	divident[n] = 0;
	// divisor <- b
	wwCopy(divisor, b, m);
	// нормализация -- сделать старший разряд divisor первым в старшем
	// (возможно неявном) слове
	shift = (wwBitSize(b + m - 1, 1) - 1) % B_PER_W;
	// нормализация не нужна?
	if (shift == 0)
		// обнуляем старшие слова q и r
		q[n - m] = 0, r[--m] = 0;
	else
		// сдвигаем divisor и divident
		shift = B_PER_W - shift,
		wwShHi(divident, n + 1, shift),
		wwShHi(divisor, m, shift);
	// строим таблицы
	_DIV_PRE_S4(w1, divisor[m - 1]);
	_MUL_PRE_S4(w2, divisor[m - 1]);
	// цикл по разрядам делимого
	for (i = n; i >= m; --i)
	{
		// q[i - m] <- divident[i] \div divisor[m - 1]
		dividentHi = divident[i];
		_DIV_DIV_S4(dividentHi, q[i - m], w1, w2);
		// divident <- divident - divisor * X^{i - m} * q[i - m]
		divident[i] ^=
			ppAddMulW(divident + i - m, divisor, m, q[i - m], stack);
		// обработаем неявный старший разряд divisor
		divident[i] ^= q[i - m];
	}
	// денормализация
	wwShLo(divident, n + 1, shift);
	// сохранить остаток
	wwCopy(r, divident, m);
	// очистить регистровые переменные
	shift = 0;
	dividentHi = 0;
}

size_t ppDiv_deep(size_t n, size_t m)
{
	return O_OF_W(n + 1 + m + 16 + 16) + ppAddMulW_deep(m);
}

void ppMod(word r[], const word a[], size_t n, const word b[], size_t m,
	void* stack)
{
	register word dividentHi;
	register word tmp;
	register size_t shift;
	size_t i;
	// переменные в stack
	word* divident;		/* нормализованное делимое (n + 1 слово) */
	word* divisor;		/* нормализованный делитель (m слов) */
	word* w1;			/* таблица частных (16 слов) */
	word* w2;			/* таблица умножения (16 слов) */
	// pre
	ASSERT(wwIsValid(a, n) && wwIsValid(b, m));
	ASSERT(m > 0 && b[m - 1] > 0);
	ASSERT(a == r || wwIsDisjoint2(a, n, r, m));
	// a < b?
	if (wwCmp2(a, n, b, m) < 0)
	{
		// r <- a
		if (n < m)
			wwSetZero(r + n, m - n), m = n;
		wwCopy(r, a, m);
		return;
	}
	// резервируем переменные в stack
	divident = (word*)stack;
	divisor = divident + n + 1;
	w1 = divisor + m;
	w2 = w1 + 16;
	stack = w2 + 16;
	// divident <- a
	wwCopy(divident, a, n);
	divident[n] = 0;
	// divisor <- b
	wwCopy(divisor, b, m);
	// нормализация -- сделать старший разряд divisor первым в старшем
	// (возможно неявном) слове
	shift = (wwBitSize(b + m - 1, 1) - 1) % B_PER_W;
	// нормализация не нужна?
	if (shift == 0)
		// обнуляем старшее слово r
		r[--m] = 0;
	else
		// сдвигаем divisor и divident
		shift = B_PER_W - shift,
		wwShHi(divident, n + 1, shift),
		wwShHi(divisor, m, shift);
	// строим таблицы
	_DIV_PRE_S4(w1, divisor[m - 1]);
	_MUL_PRE_S4(w2, divisor[m - 1]);
	// цикл по разрядам делимого
	for (i = n; i >= m; --i)
	{
		// tmp <- divident[i] \div (1, divisor[m - 1])
		dividentHi = divident[i];
		_DIV_DIV_S4(dividentHi, tmp, w1, w2);
		// divident <- divident - divisor * X^{i - m} * tmp
		divident[i] ^=
			ppAddMulW(divident + i - m, divisor, m, tmp, stack);
		// обработаем неявный старший разряд divisor
		divident[i] ^= tmp;
	}
	// денормализация
	wwShLo(divident, n + 1, shift);
	// сохранить остаток
	wwCopy(r, divident, m);
	// очистить регистровые переменные
	shift = 0;
	tmp = 0;
	dividentHi = 0;
}

size_t ppMod_deep(size_t n, size_t m)
{
	return O_OF_W(n + 1 + m + 16 + 16) + ppAddMulW_deep(m);
}

/*
*******************************************************************************
Алгоритм Евклида

В функциях ppGCD(), ppExGCD() реализованы бинарные алгоритмы,
не требующие прямых делений.

В функции ppExGCD() пересчитываются многочлены da, db, da0, db0
такие, что
	da0 * aa + db0 * bb = u,
	da * aa + db * bb = v,
где aa = a / x^s, bb = b / x^s, s -- max целое т.ч. x^s | a и x^s | b.
Многочлены u и v поддерживают вычисление \gcd(aa, bb). Если u >= v, то u
заменяется на u + v, а если u < v, то v заменяется на v + u.
Как только u == 0 вычисления останавливаются и возвращается тройка
	(2^s * v, da, db).
В функции ppExGCD() реализован алгоритм:
	u <- aa
	da0 <- 1, db0 <- 0
	v <- bb
	da <- 0, db <- 1
	пока (u != 0)
	{
		пока (u делится на x)
			u <- u / x
			если (da0 и db0 делятся на x)
				da0 <- da0 / x, db0 <- db0 / x
			иначе
				da0 <- (da0 + bb) / x, db0 <- (db0 + aa) / x
		пока (v делится на x)
			v <- v / x
			если (da и db делятся на x)
				da <- da / x, db <- db / x
			иначе
				da <- (da + bb) / x, db <- (db + aa) / x
		если (u >= v)
			u <- u + v
			da0 <- da0 + da, db0 <- db0 + db
		иначе // u < v
			v <- v + u
			da <- da + da0, db <- db + db0
	}
*******************************************************************************
*/

void ppGCD(word d[], const word a[], size_t n, const word b[], size_t m,
	void* stack)
{
	register size_t s;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	stack = v + m;
	// pre
	ASSERT(wwIsDisjoint2(a, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(b, m, d, MIN2(n, m)));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
	// d <- 0
	wwSetZero(d, MIN2(n, m));
	// u <- a, v <- b
	wwCopy(u, a, n);
	wwCopy(v, b, m);
	// найти максимальное s т.ч. x^s | u и x^s | v
	s = utilMin(2, wwLoZeroBits(u, n), wwLoZeroBits(v, m));
	// u <- u / x^s, v <- v / x^s
	wwShLo(u, n, s);
	n = wwWordSize(u, n);
	wwShLo(v, m, s);
	m = wwWordSize(v, m);
	// итерации
	do
	{
		wwShLo(u, n, wwLoZeroBits(u, n));
		n = wwWordSize(u, n);
		wwShLo(v, m, wwLoZeroBits(v, m));
		m = wwWordSize(v, m);
		// u >= v?
		if (wwCmp2(u, n, v, m) >= 0)
			// u <- u + v
			wwXor2(u, v, m);
		else
			// v <- v + u
			wwXor2(v, u, n);
	}
	while (!wwIsZero(u, n));
	// d <- v
	wwCopy(d, v, m);
	// d <- d * x^s
	wwShHi(d, W_OF_B(wwBitSize(d, m) + s), s);
	// очистка
	s = 0;
}

size_t ppGCD_deep(size_t n, size_t m)
{
	return O_OF_W(n + m);
}

void ppExGCD(word d[], word da[], word db[], const word a[], size_t n,
	const word b[], size_t m, void* stack)
{
	register size_t s;
	size_t nu, mv;
	// переменные в stack
	word* aa = (word*)stack;
	word* bb = aa + n;
	word* u = bb + m;
	word* v = u + n;
	word* da0 = v + m;
	word* db0 = da0 + m;
	stack = db0 + n;
	// pre
	ASSERT(wwIsDisjoint3(da, m, db, n, d, MIN2(n, m)));
	ASSERT(wwIsDisjoint2(a, n, da, m));
	ASSERT(wwIsDisjoint2(b, m, da, m));
	ASSERT(wwIsDisjoint2(a, n, db, n));
	ASSERT(wwIsDisjoint2(b, m, db, n));
	ASSERT(!wwIsZero(a, n) && !wwIsZero(b, m));
	// d <- 0, da0 <- 1, db0 <- 0, da <- 0, db <- 1
	wwSetZero(d, MIN2(n, m));
	wwSetW(da0, m, 1);
	wwSetZero(db0, n);
	wwSetZero(da, m);
	wwSetW(db, n, 1);
	// найти максимальное s т.ч. 2^s | aa и 2^s | bb
	s = utilMin(2, wwLoZeroBits(a, n), wwLoZeroBits(b, m));
	// aa <- a / x^s, bb <- b / x^s
	wwCopy(aa, a, n), wwShLo(aa, n, s), n = wwWordSize(aa, n);
	wwCopy(bb, b, m), wwShLo(bb, m, s), m = wwWordSize(bb, m);
	// u <- aa, v <- bb
	wwCopy(u, aa, n);
	wwCopy(v, bb, m);
	nu = n, mv = m;
	// итерации
	do
	{
		// пока u делится на x
		for (; wwTestBit(u, 0) == 0; wwShLo(u, nu, 1))
			if (wwTestBit(da0, 0) == 0)
			{
				// da0 <- da0 / x, db0 <- db0 / x
				wwShLo(da0, m, 1);
				ASSERT(wwTestBit(db0, 0) == 0);
				wwShLo(db0, n, 1);
			}
			else
			{
				// da0 <- (da0 + bb) / x, db0 <- (db0 + aa) / x
				wwXor2(da0, bb, m), wwShLo(da0, m, 1);
				ASSERT(wwTestBit(db0, 0) == 1);
				wwXor2(db0, aa, n), wwShLo(db0, n, 1);
			}
		// пока v делится на x
		for (; wwTestBit(v, 0) == 0; wwShLo(v, mv, 1))
			if (wwTestBit(da, 0) == 0)
			{
				// da <- da / x, db <- db / x
				wwShLo(da, m, 1);
				ASSERT(wwTestBit(db, 0) == 0);
				wwShLo(db, n, 1);
			}
			else
			{
				// da <- (da + bb) / x, db <- (db + aa) / x
				wwXor2(da, bb, m), wwShLo(da, m, 1);
				ASSERT(wwTestBit(db, 0) == 1);
				wwXor2(db, aa, n), wwShLo(db, n, 1);
			}
		// нормализация
		nu = wwWordSize(u, nu);
		mv = wwWordSize(v, mv);
		// u >= v?
		if (wwCmp2(u, nu, v, mv) >= 0)
		{
			// u <- u + v, da0 <- da0 + da, db0 <- db0 + db
			wwXor2(u, v, mv);
			wwXor2(da0, da, m);
			wwXor2(db0, db, n);
		}
		else
		{
			// v <- v + u, da <- da + da0, db <- db + db0
			wwXor2(v, u, nu);
			wwXor2(da, da0, m);
			wwXor2(db, db0, n);
		}
	}
	while (!wwIsZero(u, nu));
	// d <- v
	wwCopy(d, v, m);
	// d <- d * 2^s
	wwShHi(d, W_OF_B(wwBitSize(d, m) + s), s);
	// очистка
	s = 0;
}

size_t ppExGCD_deep(size_t n, size_t m)
{
	return O_OF_W(3 * n + 3 * m);
}

/*
*******************************************************************************
Модулярная арифметика

В ppDivMod() реализован упрощенный вариант ppExGCD(): рассчитываются
только da0, da, причем da0 = divident (а не 1).

\todo Реализовать в ppDivMod() случай произвольного (а не только
со свободным членом) mod.

\todo Хотя в ppDivMod() есть предусловие (a, mod) = 1 может оказаться так,
что оно не будет выполнено в верхней программе. Отказаться от ASSERT в этой
ситуации (аналогично -- в zz).
*******************************************************************************
*/

void ppMulMod(word c[], const word a[], const word b[], const word mod[],
	size_t n, void* stack)
{
	word* prod = (word*)stack;
	stack = prod + 2 * n;
	// pre
	ASSERT(wwCmp(a, mod, n) < 0 && wwCmp(b, mod, n) < 0);
	ASSERT(n > 0 && mod[n - 1] != 0);
	ASSERT(wwIsValid(c, n));
	// умножить
	ppMul(prod, a, n, b, n, stack);
	// привести по модулю
	ppMod(c, prod, 2 * n, mod, n, stack);
}

size_t ppMulMod_deep(size_t n)
{
	return O_OF_W(2 * n) +
		utilMax(2,
			ppMul_deep(n, n),
			ppMod_deep(2 * n, n));
}

void ppSqrMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	word* sqr = (word*)stack;
	stack = sqr + 2 * n;
	// pre
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(n > 0 && mod[n - 1] != 0);
	ASSERT(wwIsValid(b, n));
	// вычисления
	ppSqr(sqr, a, n, stack);
	ppMod(b, sqr, 2 * n, mod, n, stack);
}

size_t ppSqrMod_deep(size_t n)
{
	return O_OF_W(2 * n) +
		utilMax(2,
			ppSqr_deep(n),
			ppMod_deep(2 * n, n));
}

void ppDivMod(word b[], const word divident[], const word a[],
	const word mod[], size_t n, void* stack)
{
	size_t nu, nv;
	// переменные в stack
	word* u = (word*)stack;
	word* v = u + n;
	word* da0 = v + n;
	word* da = da0 + n;
	stack = da + n;
	// pre
	ASSERT(wwCmp(a, mod, n) < 0);
	ASSERT(wwCmp(divident, mod, n) < 0);
	ASSERT(n > 0 && mod[n - 1] != 0 && wwTestBit(mod, 0));
	ASSERT(wwIsValid(b, n));
	// da0 <- divident, da <- 0
	wwCopy(da0, divident, n);
	wwSetZero(da, n);
	// u <- a, v <- mod
	wwCopy(u, a, n);
	nu = wwWordSize(u, n);
	wwCopy(v, mod, n);
	nv = n;
	// итерации со следующими инвариантами:
	//	da0 * a \equiv divident * u \mod mod
	//	da * a \equiv divident * v \mod mod
	while (!wwIsZero(u, nu))
	{
		// пока u делится на x
		for (; wwTestBit(u, 0) == 0; wwShLo(u, nu, 1))
			if (wwTestBit(da0, 0) == 0)
				// da0 <- da0 / x
				wwShLo(da0, n, 1);
			else
				// da0 <- (da0 + mod) / 2
				wwXor2(da0, mod, n), wwShLo(da0, n, 1);
		// пока v делится на x
		for (; wwTestBit(v, 0) == 0; wwShLo(v, nv, 1))
			if (wwTestBit(da, 0) == 0)
				// da <- da / x
				wwShLo(da, n, 1);
			else
				// da <- (da + mod) / 2
				wwXor2(da, mod, n), wwShLo(da, n, 1);
		// нормализация
		nu = wwWordSize(u, nu);
		nv = wwWordSize(v, nv);
		// u >= v?
		if (wwCmp2(u, nu, v, nv) >= 0)
		{
			// u <- u + v, da0 <- da0 + da
			wwXor2(u, v, nv);
			wwXor2(da0, da, n);
		}
		else
		{
			// v <- v + u, da <- da + da0
			wwXor2(v, u, nu);
			wwXor2(da, da0, n);
		}
	}
	// здесь v == \gcd(a, mod)
	EXPECT(wwIsW(v, nv, 1));
	// \gcd(a, mod) == 1 ? b <- da : b <- 0
	if (wwIsW(v, nv, 1))
		wwCopy(b, da, n);
	else
		wwSetZero(b, n);
}

size_t ppDivMod_deep(size_t n)
{
	return O_OF_W(4 * n);
}

void ppInvMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	word* divident = (word*)stack;
	stack = divident + n;
	wwSetW(divident, n, 1);
	ppDivMod(b, divident, a, mod, n, stack);
}

size_t ppInvMod_deep(size_t n)
{
	return O_OF_W(n) + ppDivMod_deep(n);
}

/*
*******************************************************************************
Редукции

Обоснование корректности ppRedTrinomial() (w == BITSPEWORD):
p(x)x^{w * i} \equiv
	p(x) x^{w * (i - mw) - mb}(x^k + 1) \equiv
	p(x) x^{w * (i - mw) - mb} + f(x)x^{w * (i - kw) - kb}
*******************************************************************************
*/

void ppRed(word a[], const word mod[], size_t n, void* stack)
{
	ppMod(a, a, 2 * n, mod, n, stack);
}

size_t ppRed_deep(size_t n)
{
	return ppMod_deep(2 * n, n);
}

void ppRedTrinomial(word a[], const pp_trinom_st* p)
{
	register word hi;
	size_t mb, mw, kb, kw;
	size_t n;
	// pre
	ASSERT(memIsValid(p, sizeof(pp_trinom_st)));
	ASSERT(wwIsValid(a, 2 * W_OF_B(p->m)));
	ASSERT(p->m % 8 != 0);
	ASSERT(p->m > p->k && p->k > 0);
	ASSERT(p->m - p->k >= B_PER_W);
	// разбор трехчлена
	mb = p->m % B_PER_W;
	mw = p->m / B_PER_W;
	kb = (p->m - p->k) % B_PER_W;
	kw = (p->m - p->k) / B_PER_W;
	// обработать старшие слова
	for (n = 2 * W_OF_B(p->m); --n > mw;)
	{
		hi = a[n];
		a[n - mw - 1] ^= hi << (B_PER_W - mb);
		a[n - mw] ^= hi >> mb;
		a[n - kw - 1] ^= kb ? hi << (B_PER_W - kb) : 0;
		a[n - kw] ^= hi >> kb;
	}
	// слово, на которое попадает моном x^m
	ASSERT(n == mw);
	hi = a[n] >> mb;
	a[0] ^= hi;
	hi <<= mb;
	if (kw < n && kb)
		a[n - kw - 1] ^= hi << (B_PER_W - kb);
	a[n - kw] ^= hi >> kb;
	a[n] ^= hi;
	// очистка
	hi = 0;
}

void ppRedPentanomial(word a[], const pp_pentanom_st* p)
{
	register word hi;
	size_t mb, mw, l1b, l1w, lb, lw, kb, kw;
	size_t n;
	// pre
	ASSERT(memIsValid(p, sizeof(pp_pentanom_st)));
	ASSERT(wwIsValid(a, 2 * W_OF_B(p->m)));
	ASSERT(p->m > p->k && p->k > p->l && p->l > p->l1 && p->l1 > 0);
	ASSERT(p->k < B_PER_W);
	ASSERT(p->m - p->k >= B_PER_W);
	// разбор пятичлена
	mb = p->m % B_PER_W;
	mw = p->m / B_PER_W;
	l1b = (p->m - p->l1) % B_PER_W;
	l1w = (p->m - p->l1) / B_PER_W;
	lb = (p->m - p->l) % B_PER_W;
	lw = (p->m - p->l) / B_PER_W;
	kb = (p->m - p->k) % B_PER_W;
	kw = (p->m - p->k) / B_PER_W;
	// обрабатываем старшие слова
	for (n = 2 * W_OF_B(p->m); --n > mw;)
	{
		hi = a[n];
		a[n - mw - 1] ^= mb ? hi << (B_PER_W - mb) : 0;
		a[n - mw] ^= hi >> mb;
		a[n - l1w - 1] ^= l1b ? hi << (B_PER_W - l1b) : 0;
		a[n - l1w] ^= hi >> l1b;
		a[n - lw - 1] ^= lb ? hi << (B_PER_W - lb) : 0;
		a[n - lw] ^= hi >> lb;
		a[n - kw - 1] ^= kb ? hi << (B_PER_W - kb) : 0;
		a[n - kw] ^= hi >> kb;
	}
	// слово, на которое попадает моном x^m
	ASSERT(n == mw);
	hi = a[n] >> mb;
	a[0] ^= hi;
	hi <<= mb;
	if (l1w < n && l1b)
		a[n - l1w - 1] ^= hi << (B_PER_W - l1b);
	a[n - l1w] ^= hi >> l1b;
	if (lw < n && lb)
		a[n - lw - 1] ^= hi << (B_PER_W - lb);
	a[n - lw] ^= hi >> lb;
	if (kw < n && kb)
		a[n - kw - 1] ^= hi << (B_PER_W - kb);
	a[n - kw] ^= hi >> kb;
	a[n] ^= hi;
	// очистка
	hi = 0;
}

void ppRedBelt(word a[])
{
	const size_t mw = W_OF_B(128);
	size_t n = 2 * mw;
	ASSERT(wwIsValid(a, 2 * mw));
	ASSERT(mw * B_PER_W == 128);
	while (--n >= mw)
	{
		a[n - mw] ^= a[n] ^ a[n] << 1 ^ a[n] << 2 ^ a[n] << 7;
		a[n - mw + 1] ^= a[n] >> (B_PER_W - 1) ^
			a[n] >> (B_PER_W - 2) ^ a[n] >> (B_PER_W - 7);
	}
}

/*
*******************************************************************************
Неприводимость

Реализован алгоритм Бен-Ора [Ben-Or M. Probabilistic algorithms in
finite fields. In Proc. 22nd IEEE Symp. Foundations Computer Science,
1981, 394--398]. По оценкам [Gao S., Panario D. Test and Construction of
Irreducible Polynomials over Finite Fields] этот алгоритм обрабатывает
случайные многочлены значительно быстрее, чем алгоритм Рабина
[Rabin M. Probabilistic algorithms in finite fields. SIAM J. Comp. 9,
1980, 273--280].

Алгоритм Рабина (m = deg(a)):
	для (i = 1,..., m)
		если (i | m && m / i -- простое && (a, x^{2^i} - x) != 1)
			возвратить 0
	если (x^{2^m} != x \mod f)
		возвратить 0
	возвратить 1

Алгоритм Бен-Ора:
	для (i = 1,..., m div 2)
		если (a, x^{2^i} - x) != 1
			возвратить 0
	возвратить 1
*******************************************************************************
*/

bool_t ppIsIrred(const word a[], size_t n, void* stack)
{
	size_t i;
	word* h = (word*)stack;
	word* d = h + n;
	stack = d + n;
	// нормализация (нужна для \mod a)
	n = wwWordSize(a, n);
	// постоянный многочлен не является неприводимым
	if (wwCmpW(a, n, 1) <= 0)
		return FALSE;
	// h <- x^2
	wwSetW(h, n, 4);
	// основной цикл
	for (i = ppDeg(a, n) / 2; i; --i)
	{
		// (h + x, a) == 1?
		wwFlipBit(h, 1);
		if (wwIsZero(h, n))
			return FALSE;
		ppGCD(d, h, n, a, n, stack);
		if (wwCmpW(d, n, 1) != 0)
			return FALSE;
		wwFlipBit(h, 1);
		// h <- h^2 \mod a
		if (i > 1)
			ppSqrMod(h, h, a, n, stack);
	}
	return TRUE;
}

size_t ppIsIrred_deep(size_t n)
{
	return O_OF_W(2 * n);
}

/*
*******************************************************************************
Минимальные многочлены

Реализован следующий алгоритм определения минимального многочлена
последовательности:
	aa <- a
	bb <- x^{2l}
	da <- 1, db <- 0
	пока (deg(aa) >= l)
	{
		[инвариант: da * a + db * x^{2l} == aa]
		(q, r) <- (bb div aa, bb mod aa)
		(db, da) <- (da, db + q da)
		(bb, aa) <- (aa, r)
	}
	вернуть da
Алгоритм формально определен в [Atti N.B., Diaz-Toca G.M., Lombardi H.
The Berlekamp-Massey Algorithm Revisited, AAECC (2006) 17: 75–82] и
неформально в [Shoup V. A Computational Introduction to Number Theory
and Algebra]. В последней работе можно найти обоснование алгоритма:
теорема 17.8, п. 17.5.1, рассуждения после теоремы 18.2.
Из этого обоснования, в частности, следует, что \deg da, \deg db <= l.
*******************************************************************************
*/

void ppMinPoly(word b[], const word a[], size_t l, void* stack)
{
	const size_t n = W_OF_B(l);
	const size_t m = W_OF_B(l + 1);
	size_t na, nb;
	// переменные в stack
	word* aa = (word*)stack;
	word* bb = aa + 2 * n;
	word* q = bb + 2 * n + 1;
	word* r = q + n + 2;
	word* da = r + 2 * n;
	word* db = da + m;
	stack = db + m + n + 2;
	// pre
	ASSERT(wwIsValid(b, m) && wwIsValid(a, 2 * n));
	// aa <- a
	wwCopy(aa, a, 2 * n);
	wwTrimHi(aa, 2 * n, 2 * l);
	na = wwWordSize(aa, 2 * n);
	// bb <- x^{2l}
	nb = W_OF_B(2 * l + 1);
	wwSetZero(bb, nb);
	wwSetBit(bb, 2 * l, 1);
	// da <- 1
	wwSetW(da, m, 1);
	// db <- 0
	wwSetZero(db, m);
	// пока deg(aa) >= len
	while (ppDeg(aa, na) + 1 > l)
	{
		size_t nq, nda;
		// (q, r) <- (bb div aa, bb mod aa)
		ppDiv(q, r, bb, nb, aa, na, stack);
		// db <- db + q * da
		nq = wwWordSize(q, nb - na + 1);
		nda = wwWordSize(da, m);
		while (nq--)
			db[nq + nda] ^= ppAddMulW(db + nq, da, nda, q[nq], stack);
		ASSERT(nq + nda <= m || wwIsZero(db, nq + nda - m));
		// da <-> db
		wwSwap(da, db, m);
		// bb <- aa
		wwCopy(bb, aa, na);
		nb = na;
		// aa <- r
		wwCopy(aa, r, na);
		na = wwWordSize(aa, na);
	}
	// b <- da
	wwCopy(b, da, m);
}

size_t ppMinPoly_deep(size_t l)
{
	const size_t n = W_OF_B(l);
	const size_t m = W_OF_B(l + 1);
	return O_OF_W(8 * n + 2 * m + 5) + ppAddMulW_deep(m);
}

void ppMinPolyMod(word b[], const word a[], const word mod[], size_t n,
	void* stack)
{
	size_t l, i;
	// раскладка стека
	word* t = (word*)stack;
	word* s = t + n;
	stack = s + 2 * n;
	// pre
	ASSERT(wwIsValid(b, n) && wwIsValid(a, n) && wwIsValid(mod, n));
	ASSERT(wwCmpW(mod, n, 1) > 0 && wwCmp(a, mod, n) < 0);
	// l <- \deg(mod)
	l = ppDeg(mod, n);
	// s[2 * l - 1 - i] <- a(x)^i при x = 0
	wwCopy(t, a, n);
	wwSetBit(s, 2 * l - 1, wwTestBit(t, 0));
	for (i = 2 * l - 1; i--;)
	{
		ppMulMod(t, t, a, mod, n, stack);
		wwSetBit(s, i, wwTestBit(t, 0));
	}
	wwTrimHi(s, 2 * n, 2 * l);
	// b <- минимальный многочлен s
	ppMinPoly(b, s, l, stack);
}

size_t ppMinPolyMod_deep(size_t n)
{
	return ppMulMod_deep(n) + ppMinPoly_deep(n * B_PER_W);
}

/*	снять подавление предупреждения C4146 */
#if defined (_MSC_VER) && (_MSC_VER >= 1200)
	#pragma warning(pop)
#endif
