/*
*******************************************************************************
\file bash_fneon.c
\brief STB 34.101.77 (bash): bash-f optimized for ARM NEON
\project bee2 [cryptographic library]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2020.10.26
\version 2020.10.26
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

// It's hard to detect ARM NEON as different compilers set different macros, gcc especially
#if 0 && !(defined(__ARM_NEON__) || defined(__ARM_NEON))
	#error "The compiler does not support ARM NEON target platform"
#endif

#if (OCTET_ORDER == BIG_ENDIAN)
	#error "ARM NEON contradicts big-endianness"
#endif

#include <arm_neon.h>

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
STORE.
*******************************************************************************
*/

#define LOAD(s) vld1q_u64((uint64_t const *) (s))
#define STORE(s,w) vst1q_u64((uint64_t *)(s), (w))
#if 0 && defined(__aarch64__)
#define LOAD(s) vld4q_u64((uint64_t const *) (s))
#define STORE(s,w) vst4q_u64((uint64_t *)(s), (w))
#endif

#define S2(w0,w1) vsetq_lane_u64(w0, vmovq_n_u64(w1), 0)
#define X2(w1,w2) veorq_u64(w1,w2)
#ifdef __aarch64__
#define X3(w1,w2,w3) veor3q_u64(w1,w2,w3)
#else
#define X3(w1,w2,w3) X2(w1,X2(w2,w3))
#endif
#define O2(w1,w2) vorrq_u64(w1,w2)
#define A2(w1,w2) vandq_u64(w1,w2)
#define NO2(w1,w2) vornq_u64(w1,w2)

#define SL2(m,a) vshlq_n_u64(a,m)
#define SR2(m,a) vshrq_n_u64(a,m)

#define P2_10(w) vextq_u64(w, w, 1)
#define P2_02(w0,w1) vsetq_lane_u64(vgetq_lane_u64(w1, 0), w0, 1)
#define P2_13(w0,w1) vsetq_lane_u64(vgetq_lane_u64(w0, 1), w1, 0)

#define R2(a,i0,i1)\
  P2_02(X2(SL2(i0,a),SR2(64-i0,a)),\
	 P2_10(X2(SL2(i1,a),SR2(64-i1,a))))

/*
*******************************************************************************
Bash-S
*******************************************************************************
*/

#define bashS(M1,N1,M2,N2, W0,W1,W2)\
	Z2 = M1(W0);\
	U0 = X3(W0, W1, W2);\
	Z1 = X2(W1, N1(U0));\
	U2 = X3(W2, M2(W2), N2(Z1));\
	U1 = X2(Z1, Z2);\
	T1 = O2(U0, U2);\
	T2 = A2(U0, U1);\
	T0 = NO2(U1, U2);\
	W1 = X2(U1, T1);\
	W2 = X2(U2, T2);\
	W0 = X2(U0, T0)

/*
*******************************************************************************
Перестановка P

Вместо перестановки P используются более простые (для реализации)
перестановки P0 и P1 такие, что P1 P0 = P^2. P0 применяется на тактах
1, 3, ...., P1 -- на тактах 2, 4, ..... P0 и P1 удобно выбирать так, что
P0 = delta P, P1 = P delta, а delta^2 = id.

Инструкции SSE2 имеют ограничения по перемешиванию 64-битных слов в регистрах.
delta, переставляющая столбцы по правилу: 01234567 -> 10234576, позволяет
сократить число инструкций по сравнению с тривиальной реализацией.

Cлова на входах тактов 2, 4, ... перемешаны относительно стандартного
порядка, поэтому сдвиговые константы на этих тактах также перемешаны.
*******************************************************************************
*/

#define bashP10(W0,W1,W2)\
	W0 = P2_10(W0);\
	W1 = P2_10(W1);\
	W2 = P2_10(W2)

#define bashPP(W0,W1,W2,W3,W4,W5)\
	T0 = W4;\
	T1 = W5;\
	W4 = P2_02(W0, W1);\
	W5 = P2_13(W0, W1);\
	W1 = P2_02(W2, W3);\
	W0 = P2_13(W2, W3);\
	W2 = T0;\
	W3 = T1

/* W0 [S0 ,S1 ] W1 [S2 ,S3 ] W2 [S4 ,S5 ] W3 [S6 ,S7 ]
   W4 [S8 ,S9 ] W5 [S10,S11] W6 [S12,S13] W7 [S14,S15]
   W8 [S16,S17] W9 [S18,S19] W10[S20,S21] W11[S22,S23]
-> W0 [S10,S15] W1 [S9 ,S12] W2 [S11,S14] W3 [S8 ,S13]
   W4 [S16,S17] W5 [S19,S18] W6 [S21,S20] W7 [S22,S23]
   W8 [S3 ,S6 ] W9 [S0 ,S5 ] W10[S2 ,S7 ] W11[S1 ,S4 ] */
#define bashP0\
	bashP10(W1, W6, W10);\
	bashPP(W1, W3, W4, W6, W8, W10);\
	bashP10(W2, W5, W9);\
	bashPP(W0, W2, W5, W7, W9, W11)

/* W0 [S0 ,S1 ] W1 [S2 ,S3 ] W2 [S4 ,S5 ] W3 [S6 ,S7 ]
   W4 [S8 ,S9 ] W5 [S10,S11] W6 [S12,S13] W7 [S14,S15]
   W8 [S16,S17] W9 [S18,S19] W10[S20,S21] W11[S22,S23]
-> W0 [S14,S10] W1 [S8 ,S12] W2 [S11,S15] W3 [S13,S9 ]
   W4 [S16,S17] W5 [S19,S18] W6 [S21,S20] W7 [S22,S23]
   W8 [S7 ,S3 ] W9 [S1 ,S5 ] W10[S2 ,S6 ] W11[S4 ,S0 ] */
#define bashP1\
	bashPP(W3, W1, W6, W4, W10, W8);\
	bashP10(W1, W6, W10);\
	bashPP(W2, W0, W7, W5, W11, W9);\
	bashP10(W2, W5, W9)

/*
*******************************************************************************
Сдвиговые константы

Cлова на входах тактов 2, 4, ... перемешаны относительно стандартного
порядка, поэтому сдвиговые константы на этих тактах также перемешиваются:
R2_X_1(a,i) = R2_X_0(a,delta(i)).
*******************************************************************************
*/

#define R2_0_0(a,i0,i1,i2,i3,i4,i5,i6,i7) R2(a,i0,i1)
#define R2_1_0(a,i0,i1,i2,i3,i4,i5,i6,i7) R2(a,i2,i3)
#define R2_2_0(a,i0,i1,i2,i3,i4,i5,i6,i7) R2(a,i4,i5)
#define R2_3_0(a,i0,i1,i2,i3,i4,i5,i6,i7) R2(a,i6,i7)
#define R2_0_1(a,i0,i1,i2,i3,i4,i5,i6,i7) R2(a,i1,i0)
#define R2_1_1(a,i0,i1,i2,i3,i4,i5,i6,i7) R2(a,i2,i3)
#define R2_2_1(a,i0,i1,i2,i3,i4,i5,i6,i7) R2(a,i4,i5)
#define R2_3_1(a,i0,i1,i2,i3,i4,i5,i6,i7) R2(a,i7,i6)

#define M1_0_0(w) R2_0_0(w, 8,56, 8,56, 8,56, 8,56)
#define M1_1_0(w) R2_1_0(w, 8,56, 8,56, 8,56, 8,56)
#define M1_2_0(w) R2_2_0(w, 8,56, 8,56, 8,56, 8,56)
#define M1_3_0(w) R2_3_0(w, 8,56, 8,56, 8,56, 8,56)
#define M1_0_1(w) R2_0_1(w, 8,56, 8,56, 8,56, 8,56)
#define M1_1_1(w) R2_1_1(w, 8,56, 8,56, 8,56, 8,56)
#define M1_2_1(w) R2_2_1(w, 8,56, 8,56, 8,56, 8,56)
#define M1_3_1(w) R2_3_1(w, 8,56, 8,56, 8,56, 8,56)
#define N1_0_0(w) R2_0_0(w,53,51,37, 3,21,19, 5,35)
#define N1_1_0(w) R2_1_0(w,53,51,37, 3,21,19, 5,35)
#define N1_2_0(w) R2_2_0(w,53,51,37, 3,21,19, 5,35)
#define N1_3_0(w) R2_3_0(w,53,51,37, 3,21,19, 5,35)
#define N1_0_1(w) R2_0_1(w,53,51,37, 3,21,19, 5,35)
#define N1_1_1(w) R2_1_1(w,53,51,37, 3,21,19, 5,35)
#define N1_2_1(w) R2_2_1(w,53,51,37, 3,21,19, 5,35)
#define N1_3_1(w) R2_3_1(w,53,51,37, 3,21,19, 5,35)
#define M2_0_0(w) R2_0_0(w,14,34,46, 2,14,34,46, 2)
#define M2_1_0(w) R2_1_0(w,14,34,46, 2,14,34,46, 2)
#define M2_2_0(w) R2_2_0(w,14,34,46, 2,14,34,46, 2)
#define M2_3_0(w) R2_3_0(w,14,34,46, 2,14,34,46, 2)
#define M2_0_1(w) R2_0_1(w,14,34,46, 2,14,34,46, 2)
#define M2_1_1(w) R2_1_1(w,14,34,46, 2,14,34,46, 2)
#define M2_2_1(w) R2_2_1(w,14,34,46, 2,14,34,46, 2)
#define M2_3_1(w) R2_3_1(w,14,34,46, 2,14,34,46, 2)
#define N2_0_0(w) R2_0_0(w, 1, 7,49,23,33,39,17,55)
#define N2_1_0(w) R2_1_0(w, 1, 7,49,23,33,39,17,55)
#define N2_2_0(w) R2_2_0(w, 1, 7,49,23,33,39,17,55)
#define N2_3_0(w) R2_3_0(w, 1, 7,49,23,33,39,17,55)
#define N2_0_1(w) R2_0_1(w, 1, 7,49,23,33,39,17,55)
#define N2_1_1(w) R2_1_1(w, 1, 7,49,23,33,39,17,55)
#define N2_2_1(w) R2_2_1(w, 1, 7,49,23,33,39,17,55)
#define N2_3_1(w) R2_3_1(w, 1, 7,49,23,33,39,17,55)

/*
*******************************************************************************
Такт
*******************************************************************************
*/

#define bashR0(i)\
	bashS(M1_0_0,N1_0_0,M2_0_0,N2_0_0, W0,W4,W8);\
	bashS(M1_1_0,N1_1_0,M2_1_0,N2_1_0, W1,W5,W9);\
	bashS(M1_2_0,N1_2_0,M2_2_0,N2_2_0, W2,W6,W10);\
	bashS(M1_3_0,N1_3_0,M2_3_0,N2_3_0, W3,W7,W11);\
	bashP0;\
	W11 = X2(W11, S2(c##i,0))

#define bashR1(i)\
	bashS(M1_0_1,N1_0_1,M2_0_1,N2_0_1, W0,W4,W8);\
	bashS(M1_1_1,N1_1_1,M2_1_1,N2_1_1, W1,W5,W9);\
	bashS(M1_2_1,N1_2_1,M2_2_1,N2_2_1, W2,W6,W10);\
	bashS(M1_3_1,N1_3_1,M2_3_1,N2_3_1, W3,W7,W11);\
	bashP1;\
	W11 = X2(W11, S2(0,c##i))

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

#if 1
void bashF(octet block_unaligned[192], void* stack)
{
	register uint64x2_t Z1, Z2, T0, T1, T2, U0, U1, U2;
	register uint64x2_t W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11;
	octet *block = (octet *)((((uintptr_t)stack) + 7) & ~((uintptr_t)7));
	ASSERT(memIsDisjoint2(block_unaligned, 192, stack, bashF_deep()));
	memCopy(block, block_unaligned, 192);

	W0 = LOAD(block + 0);
	W1 = LOAD(block + 16);
	W2 = LOAD(block + 32);
	W3 = LOAD(block + 48);
	W4 = LOAD(block + 64);
	W5 = LOAD(block + 80);
	W6 = LOAD(block + 96);
	W7 = LOAD(block + 112);
	W8 = LOAD(block + 128);
	W9 = LOAD(block + 144);
	W10 = LOAD(block + 160);
	W11 = LOAD(block + 176);
	bashF0;
	STORE(block + 0, W0);
	STORE(block + 16, W1);
	STORE(block + 32, W2);
	STORE(block + 48, W3);
	STORE(block + 64, W4);
	STORE(block + 80, W5);
	STORE(block + 96, W6);
	STORE(block + 112, W7);
	STORE(block + 128, W8);
	STORE(block + 144, W9);
	STORE(block + 160, W10);
	STORE(block + 176, W11);
	memCopy(block_unaligned, block, 192);
}
#endif

size_t bashF_deep()
{
	return 192+8;
}

#if 0
#include <assert.h>
void bashF(octet block[192], void* stack)
{
  uint64_t const u[2] = { 0x8000000170000001ull, 0xf000000180000002ull, };
  uint64_t const ul[2] = { 0x00000002e0000002ull, 0xe000000300000004ull, };
  uint64_t const ur[2] = { 0x40000000b8000000ull, 0x78000000c0000001ull, };
  uint64_t const urot[2] = { 0x00000002e0000003ull, 0xc00000060000000bull, };
  uint64_t v[2];
  uint64x2_t a = S2(0x8000000170000001ull, 0xf000000180000002ull), b, c;
  uint64x2x4_t w[3];
  STORE(v, a);
  assert(u[0] == v[0] && u[1] == v[1]);
  a = LOAD(u);
  STORE(v, a);
  assert(u[0] == v[0] && u[1] == v[1]);
  b = X2(a, a);
  STORE(v, b);
  assert(0ull == v[0] && 0ull == v[1]);
  b = O2(a, a);
  STORE(v, b);
  assert(u[0] == v[0] && u[1] == v[1]);
  b = A2(a, a);
  STORE(v, b);
  assert(u[0] == v[0] && u[1] == v[1]);
  b = A2(a, X2(a, a));
  STORE(v, b);
  assert(0ull == v[0] && 0ull == v[1]);

  b = NO2(a, X2(a, a));
  STORE(v, b);
  assert(~0ull == v[0] && ~0ull == v[1]);
  b = NO2(X2(a, a), a);
  STORE(v, b);
  assert(~u[0] == v[0] && ~u[1] == v[1]);

  b = SL2(1, a);
  STORE(v, b);
  assert(ul[0] == v[0] && ul[1] == v[1]);
  b = SR2(1, a);
  STORE(v, b);
  assert(ur[0] == v[0] && ur[1] == v[1]);

  b = P2_10(a);
  STORE(v, b);
  assert(u[1] == v[0] && u[0] == v[1]);
  b = P2_02(SL2(1,a), SR2(1,a));
  STORE(v, b);
  assert(ul[0] == v[0] && ur[0] == v[1]);
  b = P2_13(SL2(1,a), SR2(1,a));
  STORE(v, b);
  assert(ul[1] == v[0] && ur[1] == v[1]);

  b = R2(a,1,2);
  STORE(v, b);
  assert(urot[0] == v[0] && urot[1] == v[1]);

  b = LOAD(block);
  b = LOAD(block+1);
  STORE(block, b);
}
#endif
