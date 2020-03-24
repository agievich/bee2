/*
*******************************************************************************
\file bash_favx512.c
\brief STB 34.101.77 (bash): bash-f optimized for AVX512
\remark AVX512 is interpreted here only as AVX512F
\project bee2 [cryptographic library]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2019.04.03
\version 2019.07.16
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*
*******************************************************************************
Архитектура AVX512 интерпретируется как AVX512F
*******************************************************************************
*/

#if !defined(__AVX512F__)
	#error "The compiler does not support AVX512 intrinsics"
#endif

#if (OCTET_ORDER == BIG_ENDIAN)
	#error "AVX512 contradicts big-endianness"
#endif


#include <immintrin.h>
#include "bee2/core/mem.h"
#include "bee2/core/u64.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bash.h"

/*
*******************************************************************************
Сокращения для используемых intrinsic

Константы для инструкций тернарной логики определяются следующим образом:

XX = a ^ b ^ c
XA = a ^ (b & c)
XO = a ^ (b | c)
XNO = a ^ ((~b) | c)

abc XX XA XO XNO
000  0  0  0  1
001  1  0  1  1
010  1  0  1  0
011  0  1  1  1
100  1  1  1  0
101  0  1  0  0
110  0  1  0  1
111  1  0  0  0
	96 78 1e 4b

\remark Указатель на память при загрузке и выгрузке в LOAD и STORE должен быть
выровнен на границу 512 бит (64 байт). LOADU и STOREU могут принимать
невыровненный указатель, но имеют большую латентность по сравнению с LOAD и
STORE.

\todo Верно ли, что инструкция VZEROALL/_mm256_zeroall() обнуляет 
512-битовые регистры полностью? Намек на это содержится вот здесь:
https://www.felixcloutier.com/x86/vzeroall
*******************************************************************************
*/

#define LOAD(s) _mm512_load_si512((void const *)(s))
#define LOADU(s) _mm512_loadu_si512((void const *)(s))
#define STORE(s,w) _mm512_store_si512((void *)(s), (w))
#define STOREU(s,w) _mm512_storeu_si512((void *)(s), (w))
#define ZEROALL _mm256_zeroall()

#define S8(w0,w1,w2,w3,w4,w5,w6,w7) _mm512_set_epi64(w7,w6,w5,w4,w3,w2,w1,w0)

#define XX8(a,b,c) _mm512_ternarylogic_epi64(a,b,c,0x96)
#define XA8(a,b,c) _mm512_ternarylogic_epi64(a,b,c,0x78)
#define XO8(a,b,c) _mm512_ternarylogic_epi64(a,b,c,0x1e)
#define XNO8(a,b,c) _mm512_ternarylogic_epi64(a,b,c,0x4b)

#define X8(w1,w2) _mm512_xor_si512(w1,w2)

#define SL8(m,a) _mm512_sllv_epi64(a,m)
#define SR8(m,a) _mm512_srlv_epi64(a,m)

#define P8(i,w) _mm512_permutexvar_epi64(i,w)

/*
*******************************************************************************
Алгоритм bash-s

\remark Расширения AVX512 содержат инструкцию тернарной логики, которая
позволяет упростить вычисление значений bash-s.
*******************************************************************************
*/

#define MF(m) ((m * 7) % 64)
#define M0(m) (m)
#define M1(m) M0(MF(m))
#define M2(m) M1(MF(m))
#define M3(m) M2(MF(m))
#define M4(m) M3(MF(m))
#define M5(m) M4(MF(m))
#define M6(m) M5(MF(m))
#define M7(m) M6(MF(m))

#define ML8(m) S8(M0(m),M1(m),M2(m),M3(m),M4(m),M5(m),M6(m),M7(m))
#define MR8(m)\
	S8(64-M0(m),64-M1(m),64-M2(m),64-M3(m),64-M4(m),64-M5(m),64-M6(m),64-M7(m))

#define M1L ML8(8)
#define M1R MR8(8)
#define N1L ML8(53)
#define N1R MR8(53)
#define M2L ML8(14)
#define M2R MR8(14)
#define N2L ML8(1)
#define N2R MR8(1)

#define bashS(W0,W1,W2, U0,U1,U2)\
	U0 = XX8(W0, W1, W2);\
	U2 = XX8(W1, SL8(N1L,U0), SR8(N1R,U0));\
	U1 = XX8(U2, SL8(M1L,W0), SR8(M1R,W0));\
	U2 = XX8(W2, SL8(N2L,U2), SR8(N2R,U2));\
	U2 = XX8(U2, SL8(M2L,W2), SR8(M2R,W2));\
	W1 = XO8(U1, U0, U2);\
	W2 = XA8(U2, U0, U1);\
	W0 = XNO8(U0, U2, U1)

/*
*******************************************************************************
Тактовая перестановка без перестановки строк
*******************************************************************************
*/

#define PI0 S8(6, 3, 0, 5, 2, 7, 4, 1)
#define PI1 S8(7, 2, 1, 4, 3, 6, 5, 0)
#define PI2 S8(1, 0, 3, 2, 5, 4, 7, 6)

#define bashP(W0,W1,W2)\
	W0 = P8(PI0, W0);\
	W1 = P8(PI1, W1);\
	W2 = P8(PI2, W2)

/*
*******************************************************************************
Такт
*******************************************************************************
*/

#define bashR0(i)\
	bashS(W0,W1,W2, U0,U1,U2);\
	bashP(W0,W1,W2);\
	W0 = X8(W0, S8(0,0,0,0,0,0,0,c##i))

#define bashR1(i)\
	bashS(W1,W2,W0, U1,U2,U0);\
	bashP(W1,W2,W0);\
	W1 = X8(W1, S8(0,0,0,0,0,0,0,c##i))

#define bashR2(i)\
	bashS(W2,W0,W1, U2,U0,U1);\
	bashP(W2,W0,W1);\
	W2 = X8(W2, S8(0,0,0,0,0,0,0,c##i))

/*
*******************************************************************************
Тактовые константы
*******************************************************************************
*/

#define c1  0x3BF5080AC8BA94B1ull
#define c2  0xC1D1659C1BBD92F6ull
#define c3  0x60E8B2CE0DDEC97Bull
#define c4  0xEC5FB8FE790FBC13ull
#define c5  0xAA043DE6436706A7ull
#define c6  0x8929FF6A5E535BFDull
#define c7  0x98BF1E2C50C97550ull
#define c8  0x4C5F8F162864BAA8ull
#define c9  0x262FC78B14325D54ull
#define c10 0x1317E3C58A192EAAull
#define c11 0x098BF1E2C50C9755ull
#define c12 0xD8EE19681D669304ull
#define c13 0x6C770CB40EB34982ull
#define c14 0x363B865A0759A4C1ull
#define c15 0xC73622B47C4C0ACEull
#define c16 0x639B115A3E260567ull
#define c17 0xEDE6693460F3DA1Dull
#define c18 0xAAD8D5034F9935A0ull
#define c19 0x556C6A81A7CC9AD0ull
#define c20 0x2AB63540D3E64D68ull
#define c21 0x155B1AA069F326B4ull
#define c22 0x0AAD8D5034F9935Aull
#define c23 0x0556C6A81A7CC9ADull
#define c24 0xDE8082CD72DEBC78ull

/*
*******************************************************************************
Алгоритм bash-f
*******************************************************************************
*/

#define bashF0\
	bashR0(1);\
	bashR1(2);\
	bashR2(3);\
	bashR0(4);\
	bashR1(5);\
	bashR2(6);\
	bashR0(7);\
	bashR1(8);\
	bashR2(9);\
	bashR0(10);\
	bashR1(11);\
	bashR2(12);\
	bashR0(13);\
	bashR1(14);\
	bashR2(15);\
	bashR0(16);\
	bashR1(17);\
	bashR2(18);\
	bashR0(19);\
	bashR1(20);\
	bashR2(21);\
	bashR0(22);\
	bashR1(23);\
	bashR2(24)

void bashF(octet block[192], void* stack)
{
	register __m512i U0, U1, U2;
	register __m512i W0, W1, W2;

	ASSERT(memIsDisjoint2(block, 192, stack, bashF_deep()));
	W0 = LOADU(block + 0);
	W1 = LOADU(block + 64);
	W2 = LOADU(block + 128);
	bashF0;
	STOREU(block + 0, W0);
	STOREU(block + 64, W1);
	STOREU(block + 128, W2);
	ZEROALL;
}

size_t bashF_deep()
{
	return 0;
}

/*
*******************************************************************************
Алгоритм bash-f на выровненной памяти
*******************************************************************************
*/

void bashF2(octet block[192])
{
	register __m512i U0, U1, U2;
	register __m512i W0, W1, W2;
		
	ASSERT(memIsValid(block, 192));
	ASSERT(memIsAligned(block, 64));
	W0 = LOAD(block + 0);
	W1 = LOAD(block + 64);
	W2 = LOAD(block + 128);
	bashF0;
	STORE(block + 0, W0);
	STORE(block + 64, W1);
	STORE(block + 128, W2);
	ZEROALL;
}
