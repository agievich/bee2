/*
*******************************************************************************
\file bash_favx2.c
\brief STB 34.101.77 (bash): bash-f AVX2 optimized
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2019.04.03
\version 2019.04.03
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#if !defined(__AVX2__)
#error "The compiler does not support AVX2 intrinsics."
#endif

#include <intrin.h>
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

#define S4(w0,w1,w2,w3) _mm256_set_epi64x(w3,w2,w1,w0)
#define X4(w1,w2) _mm256_xor_si256(w1,w2)
#define O4(w1,w2) _mm256_or_si256(w1,w2)
#define A4(w1,w2) _mm256_and_si256(w1,w2)
#define NA4(w1,w2) _mm256_andnot_si256(w2,w1) /* (~w1) & w2 */

#define SL4(m,a) _mm256_sllv_epi64(a,m)
#define SR4(m,a) _mm256_srlv_epi64(a,m)
#define R4(a,i0,i1,i2,i3) X4(SL4(S4(i0,i1,i2,i3),a),SR4(S4(64-i0,64-i1,64-i2,64-i3),a))

#define PERM4X64(w,i) _mm256_permute4x64_epi64(w,i)
#define PERM2X128(w0,w1,i) _mm256_permute2x128_si256(w0,w1,i)

/*
*******************************************************************************
Алгоритм bash-s

\remark Расширения AVX2 не содержат инструкцию "ornot", поэтому используется
"andnot" и инвертированное представление, а s-блок реализуется двумя способами:
s0 и s1 - на чётных и нечётных итерациях с выполнением свойства
s1(s0(w3)) = s(s(w3)).
*******************************************************************************
*/

#define bashSS(U0,U1,U2, T0,T1,T2) \
  do { \
    T1 = O4(U0, U2); \
    T2 = A4(U0, U1); \
    T0 = NA4(U2, U1); \
  } while (0)

#define bashS(SS, M1,N1,M2,N2, W0,W1,W2) \
  do { \
    S2 = M1(W0); \
    U0 = X4(W0, X4(W1, W2)); \
    S1 = X4(W1, N1(U0)); \
    U2 = X4(X4(W2, M2(W2)), N2(S1)); \
    U1 = X4(S1, S2); \
    SS; \
    W1 = X4(U1, T1); \
    W2 = X4(U2, T2); \
    W0 = X4(U0, T0); \
  } while (0)

#define bashS0(M1,N1,M2,N2, W0,W1,W2) \
  bashS(bashSS(U0,U1,U2, T0,T1,T2), M1,N1,M2,N2, W0,W1,W2)

#define bashS1(M1,N1,M2,N2, W0,W1,W2) \
  bashS(bashSS(U0,U2,U1, T0,T2,T1), M1,N1,M2,N2, W0,W1,W2)

/*
*******************************************************************************
Тактовая перестановка

\remark Тактовая перестановка слов является сложной операцией и реализована
двумя способами: p0 и p1 - на чётных и нечётных итерациях с выполнением
свойства p1(p0(.)) = p(p(.)), где p0 и p1 имеют более простой вид, по сравнению
с p. Это приводит к тому, что слова на входах нечётных итераций перемешаны,
поэтому сдвиговые константы на нечётных итерациях перемешаны соответствующим
образом.
*******************************************************************************
*/

/* S0,S1,S2,S3 S4,S5,S6,S7 -> S1,S0,S3,S2 S5,S4,S7,S6
    w0=S0,S1,S2,S3 w1=S4,S5,S6,S7
 -> s0=S1,S0,S3,S2 s1=S5,S4,S7,S6
*/
#define PP01(W0,W1, S0,S1) \
  do { \
    S0 = PERM4X64(W0, 0xb1); \
    S1 = PERM4X64(W1, 0xb1); \
  } while (0)

/* S16,S17,S18,S19 S20,S21,S22,S23 -> S22,S19,S16,S21 S18,S23,S20,S17
    w4=S16,S17,S18,S19 w5=S20,S21,S22,S23
 -> u4=S16,S19,S18,S17 u5=S20,S23,S22,S21
 -> t4=S16,S19,S22,S21 t5=S20,S23,S18,S17
 -> s4=S22,S19,S16,S21 s5=S18,S23,S20,S17
*/
#define PP45_1(W4,W5, U4,U5,T4,T5) \
  do { \
    U4 = PERM4X64(W4, 0x6c); \
    U5 = PERM4X64(W5, 0x6c); \
    T4 = PERM2X128(U4, U5, 0x30); \
    T5 = PERM2X128(U4, U5, 0x12); \
  } while (0)
#define PP45_2(T4,T5, S4,S5) \
  do { \
    S4 = PERM4X64(T4, 0xc6); \
    S5 = PERM4X64(T5, 0xc6); \
  } while (0)

#define bashP(W0,W1,W2,W3,W4,W5 ,Y0,Y1,Y2,Y3,Y4,Y5) \
  do { \
    PP45_1(W4,W5 ,U0,U1,T0,T1); \
    PP01(W0,W1, Y4,Y5); \
    Y0=W2; Y1=W3; \
    PP45_2(T0,T1, Y2,Y3); \
  } while(0)

#define bashP0 \
  bashP(W0,W1,W2,W3,W4,W5 ,W0,W1,W2,W3,W4,W5)

#define bashP1 \
  bashP(W0,W1,W2,W3,W4,W5 ,W0,W1,W3,W2,W5,W4)

/*
*******************************************************************************
Сдвиговые константы

\remark Слова на входах нечётных итераций перемешаны, поэтому сдвиговые
константы на нечётных итерациях перемешаны соответствующим образом.
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

#define bashR0(i) \
  do { \
    bashS0(M1L_0,N1L_0,M2L_0,N2L_0, W0,W2,W4); \
    bashS0(M1R_0,N1R_0,M2R_0,N2R_0, W1,W3,W5); \
    bashP0; \
    W4 = X4(W4, S4(C##i,0,0,0)); \
  } while (0)

#define bashR1(i) \
  do { \
    bashS1(M1L_1,N1L_1,M2L_1,N2L_1, W0,W2,W4); \
    bashS1(M1R_1,N1R_1,M2R_1,N2R_1, W1,W3,W5); \
    bashP1; \
    W5 = X4(W5, S4(0,0,0,C##i)); \
  } while (0)

/*
*******************************************************************************
Тактовые константы
*******************************************************************************
*/

#define C0 0x3bf5080ac8ba94b1ull
#define C1 0xc1d1659c1bbd92f6ull
#define C2 0x60e8b2ce0ddec97bull
#define C3 0xec5fb8fe790fbc13ull
#define C4 0xaa043de6436706a7ull
#define C5 0x8929ff6a5e535bfdull
#define C6 0x98bf1e2c50c97550ull
#define C7 0x4c5f8f162864baa8ull
#define C8 0x262fc78b14325d54ull
#define C9 0x1317e3c58a192eaaull
#define C10 0x98bf1e2c50c9755ull
#define C11 0xd8ee19681d669304ull
#define C12 0x6c770cb40eb34982ull
#define C13 0x363b865a0759a4c1ull
#define C14 0xc73622b47c4c0aceull
#define C15 0x639b115a3e260567ull
#define C16 0xede6693460f3da1dull
#define C17 0xaad8d5034f9935a0ull
#define C18 0x556c6a81a7cc9ad0ull
#define C19 0x2ab63540d3e64d68ull
#define C20 0x155b1aa069f326b4ull
#define C21 0xaad8d5034f9935aull
#define C22 0x556c6a81a7cc9adull
#define C23 0xde8082cd72debc78ull

/*
*******************************************************************************
Алгоритм bash-f (шаговая функция)
*******************************************************************************
*/

#define bashF0 \
  do { \
    bashR0(0); \
    bashR1(1); \
    bashR0(2); \
    bashR1(3); \
    bashR0(4); \
    bashR1(5); \
    bashR0(6); \
    bashR1(7); \
    bashR0(8); \
    bashR1(9); \
    bashR0(10); \
    bashR1(11); \
    bashR0(12); \
    bashR1(13); \
    bashR0(14); \
    bashR1(15); \
    bashR0(16); \
    bashR1(17); \
    bashR0(18); \
    bashR1(19); \
    bashR0(20); \
    bashR1(21); \
    bashR0(22); \
    bashR1(23); \
  } while (0)

/*
*******************************************************************************
Алгоритм bash-f с использованием выровненной памяти
*******************************************************************************
*/

static void bashF0_avx2(octet S[192])
{
  u256 S1, S2, T0, T1, T2, U0, U1, U2;
  u256 W0 = LOAD(S +   0);
  u256 W1 = LOAD(S +  32);
  u256 W2 = LOAD(S +  64);
  u256 W3 = LOAD(S +  96);
  u256 W4 = LOAD(S + 128);
  u256 W5 = LOAD(S + 160);

  bashF0;

  STORE(S +   0, W0);
  STORE(S +  32, W1);
  STORE(S +  64, W2);
  STORE(S +  96, W3);
  STORE(S + 128, W4);
  STORE(S + 160, W5);
}

/*
*******************************************************************************
Алгоритм bash-f с использованием невыровненной памяти
*******************************************************************************
*/

static void bashF0_avx2u(octet S[192])
{
  u256 S1, S2, T0, T1, T2, U0, U1, U2;
  u256 W0 = LOADU(S +   0);
  u256 W1 = LOADU(S +  32);
  u256 W2 = LOADU(S +  64);
  u256 W3 = LOADU(S +  96);
  u256 W4 = LOADU(S + 128);
  u256 W5 = LOADU(S + 160);

  bashF0;

  STOREU(S +   0, W0);
  STOREU(S +  32, W1);
  STOREU(S +  64, W2);
  STOREU(S +  96, W3);
  STOREU(S + 128, W4);
  STOREU(S + 160, W5);
}

void bashF(octet block[192])
{
#if (OCTET_ORDER == BIG_ENDIAN)
  u64* s = (u64*)block;
  u64Rev2(s, 24);
#endif
  bashF0_avx2u(block);
#if (OCTET_ORDER == BIG_ENDIAN)
  u64Rev2(s, 24);
#endif
}
