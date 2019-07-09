/*
*******************************************************************************
\file bash_favx2.c
\brief STB 34.101.77 (bash): bash-f optimized for AVX2
\project bee2 [cryptographic library]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2019.04.03
\version 2019.07.09
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#ifndef __AVX2__
	#error "The compiler does not support AVX2 intrinsics"
#endif

#if (OCTET_ORDER == BIG_ENDIAN)
	#error "AVX2 contradicts big-endianness"
#endif

#include <immintrin.h>

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/u64.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bash.h"

typedef __m256i u256;

/*
*******************************************************************************
Сокращения для используемых intrinsic

\remark Указатель на память при загрузке и выгрузке в LOAD и STORE должен быть
выровнен на границу 256 бит (32 байт). LOADU и STOREU могут принимать
невыровненный указатель, но имеют большую латентность по сравнению с LOAD и 
STORE.
*******************************************************************************
*/

#define LOAD(s) _mm256_load_si256((__m256i const *)(s))
#define LOADU(s) _mm256_loadu_si256((__m256i const *)(s))
#define STORE(s,w) _mm256_store_si256((__m256i *)(s), (w))
#define STOREU(s,w) _mm256_storeu_si256((__m256i *)(s), (w))
#define ZEROALL _mm256_zeroall()

#define S4(w0,w1,w2,w3) _mm256_set_epi64x(w3,w2,w1,w0)
#define X4(w1,w2) _mm256_xor_si256(w1,w2)
#define O4(w1,w2) _mm256_or_si256(w1,w2)
#define A4(w1,w2) _mm256_and_si256(w1,w2)
#define NA4(w1,w2) _mm256_andnot_si256(w2,w1) /* (~w1) & w2 */

#define SL4(m,a) _mm256_sllv_epi64(a,m)
#define SR4(m,a) _mm256_srlv_epi64(a,m)
#define R4(a,i0,i1,i2,i3)\
	X4(SL4(S4(i0,i1,i2,i3),a),SR4(S4(64-i0,64-i1,64-i2,64-i3),a))

#define PERM4X64(w,i) _mm256_permute4x64_epi64(w,i)
#define PERM2X128(w0,w1,i) _mm256_permute2x128_si256(w0,w1,i)

/*
*******************************************************************************
Bash-S

AVX2 не содержит инструкцию "ornot", поэтому используется инструкция
"andnot" с инвертированием операндов. 

Вместо S-блока S используются S-блоки S0 и S1 такие, что S1 S0 = S^2.
S0 применяется на тактах  1, 3, ...., S1 -- на тактах 2, 4, .....
*******************************************************************************
*/

#define bashSS(U0,U1,U2, T0,T1,T2)\
	T1 = O4(U0, U2);\
	T2 = A4(U0, U1);\
	T0 = NA4(U2, U1)

#define bashS(SS, M1,N1,M2,N2, W0,W1,W2)\
	S2 = M1(W0);\
	U0 = X4(W0, X4(W1, W2));\
	S1 = X4(W1, N1(U0));\
	U2 = X4(X4(W2, M2(W2)), N2(S1));\
	U1 = X4(S1, S2);\
	SS;\
	W1 = X4(U1, T1);\
	W2 = X4(U2, T2);\
	W0 = X4(U0, T0)

#define bashS0(M1,N1,M2,N2, W0,W1,W2)\
	bashS(bashSS(U0,U1,U2, T0,T1,T2), M1,N1,M2,N2, W0,W1,W2)

#define bashS1(M1,N1,M2,N2, W0,W1,W2)\
	bashS(bashSS(U0,U2,U1, T0,T2,T1), M1,N1,M2,N2, W0,W1,W2)

/*
*******************************************************************************
Перестановка P

Вместо перестановки P используются более простые (для реализации) 
перестановки P0 и P1 такие, что P1 P0 = P^2. P0 применяется на тактах  
1, 3, ...., P1 -- на тактах 2, 4, ..... 

Cлова на входах тактов 2, 4, ... перемешаны относительно стандартного 
порядка, поэтому сдвиговые константы на этих тактах также перемешаны.
*******************************************************************************
*/

/* S0,S1,S2,S3 S4,S5,S6,S7 -> S1,S0,S3,S2 S5,S4,S7,S6
    w0=S0,S1,S2,S3 w1=S4,S5,S6,S7
 -> s0=S1,S0,S3,S2 s1=S5,S4,S7,S6
*/
#define PP01(W0,W1, S0,S1)\
	S0 = PERM4X64(W0, 0xB1);\
	S1 = PERM4X64(W1, 0xB1)

/* S16,S17,S18,S19 S20,S21,S22,S23 -> S22,S19,S16,S21 S18,S23,S20,S17
    w4=S16,S17,S18,S19 w5=S20,S21,S22,S23
 -> u4=S16,S19,S18,S17 u5=S20,S23,S22,S21
 -> t4=S16,S19,S22,S21 t5=S20,S23,S18,S17
 -> s4=S22,S19,S16,S21 s5=S18,S23,S20,S17
*/
#define PP45_1(W4,W5, U4,U5,T4,T5)\
	U4 = PERM4X64(W4, 0x6C);\
	U5 = PERM4X64(W5, 0x6C);\
	T4 = PERM2X128(U4, U5, 0x30);\
	T5 = PERM2X128(U4, U5, 0x12)

#define PP45_2(T4,T5, S4,S5)\
	S4 = PERM4X64(T4, 0xC6);\
	S5 = PERM4X64(T5, 0xC6)

#define bashP(W0,W1,W2,W3,W4,W5 ,Y0,Y1,Y2,Y3,Y4,Y5)\
	PP45_1(W4,W5 ,U0,U1,T0,T1);\
	PP01(W0,W1, Y4,Y5);\
	Y0 = W2; Y1 = W3;\
	PP45_2(T0,T1, Y2,Y3);\

#define bashP0\
  bashP(W0,W1,W2,W3,W4,W5 ,W0,W1,W2,W3,W4,W5)

#define bashP1\
  bashP(W0,W1,W2,W3,W4,W5 ,W0,W1,W3,W2,W5,W4)

/*
*******************************************************************************
Сдвиговые константы


Cлова на входах тактов 2, 4, ... перемешаны относительно стандартного
порядка, поэтому сдвиговые константы на этих тактах также перемешиваются.
*******************************************************************************
*/

#define R4L_0(a,i0,i1,i2,i3,i4,i5,i6,i7) R4(a,i0,i1,i2,i3)
#define R4R_0(a,i0,i1,i2,i3,i4,i5,i6,i7) R4(a,i4,i5,i6,i7)
#define R4L_1(a,i0,i1,i2,i3,i4,i5,i6,i7) R4(a,i7,i2,i1,i4)
#define R4R_1(a,i0,i1,i2,i3,i4,i5,i6,i7) R4(a,i3,i6,i5,i0)

#define M1L_0(w) R4L_0(w, 8,56, 8,56, 8,56, 8,56)
#define M1R_0(w) R4R_0(w, 8,56, 8,56, 8,56, 8,56)
#define M1L_1(w) R4L_1(w, 8,56, 8,56, 8,56, 8,56)
#define M1R_1(w) R4R_1(w, 8,56, 8,56, 8,56, 8,56)
#define N1L_0(w) R4L_0(w,53,51,37, 3,21,19, 5,35)
#define N1R_0(w) R4R_0(w,53,51,37, 3,21,19, 5,35)
#define N1L_1(w) R4L_1(w,53,51,37, 3,21,19, 5,35)
#define N1R_1(w) R4R_1(w,53,51,37, 3,21,19, 5,35)
#define M2L_0(w) R4L_0(w,14,34,46, 2,14,34,46, 2)
#define M2R_0(w) R4R_0(w,14,34,46, 2,14,34,46, 2)
#define M2L_1(w) R4L_1(w,14,34,46, 2,14,34,46, 2)
#define M2R_1(w) R4R_1(w,14,34,46, 2,14,34,46, 2)
#define N2L_0(w) R4L_0(w, 1, 7,49,23,33,39,17,55)
#define N2R_0(w) R4R_0(w, 1, 7,49,23,33,39,17,55)
#define N2L_1(w) R4L_1(w, 1, 7,49,23,33,39,17,55)
#define N2R_1(w) R4R_1(w, 1, 7,49,23,33,39,17,55)

/*
*******************************************************************************
Такт
*******************************************************************************
*/

#define bashR0(i)\
	bashS0(M1L_0,N1L_0,M2L_0,N2L_0, W0,W2,W4);\
	bashS0(M1R_0,N1R_0,M2R_0,N2R_0, W1,W3,W5);\
	bashP0;\
	W4 = X4(W4, S4(c##i,0,0,0))

#define bashR1(i)\
	bashS1(M1L_1,N1L_1,M2L_1,N2L_1, W0,W2,W4);\
	bashS1(M1R_1,N1R_1,M2R_1,N2R_1, W1,W3,W5);\
	bashP1;\
	W5 = X4(W5, S4(0,0,0,c##i))

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
	bashR0(3);\
	bashR1(4);\
	bashR0(5);\
	bashR1(6);\
	bashR0(7);\
	bashR1(8);\
	bashR0(9);\
	bashR1(10);\
	bashR0(11);\
	bashR1(12);\
	bashR0(13);\
	bashR1(14);\
	bashR0(15);\
	bashR1(16);\
	bashR0(17);\
	bashR1(18);\
	bashR0(19);\
	bashR1(20);\
	bashR0(21);\
	bashR1(22);\
	bashR0(23);\
	bashR1(24)

void bashF(octet block[192], void* stack)
{
	register u256 S1, S2, T0, T1, T2, U0, U1, U2;
	register u256 W0, W1, W2, W3, W4, W5;

	ASSERT(memIsDisjoint2(block, 192, stack, bashF_deep()));
	W0 = LOADU(block + 0);
	W1 = LOADU(block + 32);
	W2 = LOADU(block + 64);
	W3 = LOADU(block + 96);
	W4 = LOADU(block + 128);
	W5 = LOADU(block + 160);
	bashF0;
	STOREU(block + 0, W0);
	STOREU(block + 32, W1);
	STOREU(block + 64, W2);
	STOREU(block + 96, W3);
	STOREU(block + 128, W4);
	STOREU(block + 160, W5);
	ZEROALL;
}

size_t bashF_deep()
{
	return 0;
}

/*
*******************************************************************************
Bash-f на выровненной памяти
*******************************************************************************
*/

void bashF2(octet block[192])
{
	register u256 S1, S2, T0, T1, T2, U0, U1, U2;
	register u256 W0, W1, W2, W3, W4, W5;

	ASSERT(memIsValid(block, 192));
	ASSERT(memIsAligned(block, 32));
	W0 = LOAD(block +   0);
	W1 = LOAD(block +  32);
	W2 = LOAD(block +  64);
	W3 = LOAD(block +  96);
	W4 = LOAD(block + 128);
	W5 = LOAD(block + 160);
	bashF0;
	STORE(block +   0, W0);
	STORE(block +  32, W1);
	STORE(block +  64, W2);
	STORE(block +  96, W3);
	STORE(block + 128, W4);
	STORE(block + 160, W5);
	ZEROALL;
}