/*
*******************************************************************************
\file bash_favx2.c
\brief STB 34.101.77 (bash): bash-f optimized for AVX2
\project bee2 [cryptographic library]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2019.04.03
\version 2019.07.16
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

/*
*******************************************************************************
Сокращения для используемых intrinsic

\remark Указатель на память при загрузке и выгрузке в LOAD и STORE должен быть
выровнен на границу 256 бит (32 байт). LOADU и STOREU могут принимать
невыровненный указатель, но имеют большую латентность по сравнению с LOAD и 
STORE. Согласно https://software.intel.com/sites/landingpage/IntrinsicsGuide/
это не так, и эти инструкции имеют одинаковые характеристики,
т.е. можно всегда использовать "невыровненные" инструкции.
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
#define NA4(w1,w2) _mm256_andnot_si256(w1,w2)

#define SL4(m,a) _mm256_sllv_epi64(a,m)
#define SR4(m,a) _mm256_srlv_epi64(a,m)
#define R4(a,i0,i1,i2,i3)\
	X4(SL4(S4(i0,i1,i2,i3),a),SR4(S4(64-i0,64-i1,64-i2,64-i3),a))

#define P4_1032(w) _mm256_permute4x64_epi64(w, 0xB1)
#define P4_0321(w) _mm256_permute4x64_epi64(w, 0x6C)
#define P4_2103(w) _mm256_permute4x64_epi64(w, 0xC6)
#define P4_0167(w0,w1) _mm256_permute2x128_si256(w0,w1,0x30)
#define P4_4523(w0,w1) _mm256_permute2x128_si256(w0,w1,0x12)

/*
*******************************************************************************
Bash-S

\remark
AVX2 не содержат инструкцию "ornot", поэтому используется инструкция
"andnot" с инвертированием операндов. 

Bash-S является композицией S-блока S3 и линейного преобразования L3.
L3 обладает следующим свойством:

L3 = inv012 L3 inv2, (1)

где inv2(w0,w1,w2) = (w0,w1,w2+1), inv012(w0,w1,w2) = (w0+1,w1+1,w2+1).

Вызовы Bash-S разделяются перестановкой P, в формальной записи
два такта можно записать так:

Bash-S^2 = S3 L3 up S3 L3,

где up(w0,w1,w2) = (w1,w2,w0) -- часть перестановки P, отвечающая за
перестановку строк. Справедливо равенство:

inv2 up = up inv0, (2)

где inv0(w0,w1,w2) = (w0+1,w1,w2). С учетом (1) и (2), получим:

Bash-S^2 = S3 inv012 L3 up inv0 S3 L3 = S1 L3 up S0 L3,

где S-блоки S0 = inv0 S3 и S1 = S3 inv012 могут быть легко выражены
через "andnot", не используя "ornot". S0 применяется на тактах  1, 3, ....,
S1 -- на тактах 2, 4, .....
*******************************************************************************
*/

#define bashSS(U0,U1,U2, T0,T1,T2)\
	T1 = O4(U0, U2);\
	T2 = A4(U0, U1);\
	T0 = NA4(U1, U2)

#define bashS(SS, M1,N1,M2,N2, W0,W1,W2)\
	Z2 = M1(W0);\
	U0 = X4(W0, X4(W1, W2));\
	Z1 = X4(W1, N1(U0));\
	U2 = X4(X4(W2, M2(W2)), N2(Z1));\
	U1 = X4(Z1, Z2);\
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
1, 3, ...., P1 -- на тактах 2, 4, ..... P0 и P1 удобно выбирать так, что
P0 = delta P, P1 = P delta, а delta^2 = id.

Инструкции AVX2 имеют ограничения по перемешиванию 64-битных слов в регистрах.
delta, переставляющая столбцы по правилу: 01234567 -> 72143650, позволяет
сократить число инструкций по сравнению с тривиальной реализацией.

Cлова на входах тактов 2, 4, ... перемешаны относительно стандартного 
порядка, поэтому сдвиговые константы на этих тактах также перемешаны.
*******************************************************************************
*/

/* W0[S0 ,S1 ,S2 ,S3 ] W1[S4 ,S5 ,S6 ,S7 ]
   W2[S8 ,S9 ,S10,S11] W3[S12,S13,S14,S15]
   W4[S16,S17,S18,S19] W5[S20,S21,S22,S23]
-> U0[S16,S19,S18,S17] U1[S20,S23,S22,S21]
   T0[S16,S19,S22,S21] T1[S20,S23,S18,S17]
   Y4[S1 ,S0 ,S3 ,S2 ] Y5[S5 ,S4 ,S7 ,S6 ]
   W0[S8 ,S9 ,S10,S11] W1[S12,S13,S14,S15]
   Y2[S22,S19,S16,S21] Y3[S18,S23,S20,S17] */
#define bashP(Y2,Y3,Y4,Y5)\
	U0 = P4_0321(W4);\
	U1 = P4_0321(W5);\
	T0 = P4_0167(U0, U1);\
	T1 = P4_4523(U0, U1);\
	Y4 = P4_1032(W0);\
	Y5 = P4_1032(W1);\
	W0 = W2;\
  W1 = W3;\
	Y2 = P4_2103(T0);\
	Y3 = P4_2103(T1)

#define bashP0\
  bashP(W2,W3,W4,W5)

#define bashP1\
  bashP(W3,W2,W5,W4)

/*
*******************************************************************************
Сдвиговые константы

Cлова на входах тактов 2, 4, ... перемешаны относительно стандартного
порядка, поэтому сдвиговые константы на этих тактах также перемешиваются:
R2_X_1(a,i) = R2_X_0(a,delta(i)).
*******************************************************************************
*/

#define R4_0_0(a,i0,i1,i2,i3,i4,i5,i6,i7) R4(a,i0,i1,i2,i3)
#define R4_1_0(a,i0,i1,i2,i3,i4,i5,i6,i7) R4(a,i4,i5,i6,i7)
#define R4_0_1(a,i0,i1,i2,i3,i4,i5,i6,i7) R4(a,i7,i2,i1,i4)
#define R4_1_1(a,i0,i1,i2,i3,i4,i5,i6,i7) R4(a,i3,i6,i5,i0)

#define M1_0_0(w) R4_0_0(w, 8,56, 8,56, 8,56, 8,56)
#define M1_1_0(w) R4_1_0(w, 8,56, 8,56, 8,56, 8,56)
#define M1_0_1(w) R4_0_1(w, 8,56, 8,56, 8,56, 8,56)
#define M1_1_1(w) R4_1_1(w, 8,56, 8,56, 8,56, 8,56)
#define N1_0_0(w) R4_0_0(w,53,51,37, 3,21,19, 5,35)
#define N1_1_0(w) R4_1_0(w,53,51,37, 3,21,19, 5,35)
#define N1_0_1(w) R4_0_1(w,53,51,37, 3,21,19, 5,35)
#define N1_1_1(w) R4_1_1(w,53,51,37, 3,21,19, 5,35)
#define M2_0_0(w) R4_0_0(w,14,34,46, 2,14,34,46, 2)
#define M2_1_0(w) R4_1_0(w,14,34,46, 2,14,34,46, 2)
#define M2_0_1(w) R4_0_1(w,14,34,46, 2,14,34,46, 2)
#define M2_1_1(w) R4_1_1(w,14,34,46, 2,14,34,46, 2)
#define N2_0_0(w) R4_0_0(w, 1, 7,49,23,33,39,17,55)
#define N2_1_0(w) R4_1_0(w, 1, 7,49,23,33,39,17,55)
#define N2_0_1(w) R4_0_1(w, 1, 7,49,23,33,39,17,55)
#define N2_1_1(w) R4_1_1(w, 1, 7,49,23,33,39,17,55)

/*
*******************************************************************************
Такт
*******************************************************************************
*/

#define bashR0(i)\
	bashS0(M1_0_0,N1_0_0,M2_0_0,N2_0_0, W0,W2,W4);\
	bashS0(M1_1_0,N1_1_0,M2_1_0,N2_1_0, W1,W3,W5);\
	bashP0;\
	W4 = X4(W4, S4(c##i,0,0,0))

#define bashR1(i)\
	bashS1(M1_0_1,N1_0_1,M2_0_1,N2_0_1, W0,W2,W4);\
	bashS1(M1_1_1,N1_1_1,M2_1_1,N2_1_1, W1,W3,W5);\
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
	register __m256i Z1, Z2, T0, T1, T2, U0, U1, U2;
	register __m256i W0, W1, W2, W3, W4, W5;

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
	register __m256i Z1, Z2, T0, T1, T2, U0, U1, U2;
	register __m256i W0, W1, W2, W3, W4, W5;

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
