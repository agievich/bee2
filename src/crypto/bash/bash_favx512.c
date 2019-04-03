/*
*******************************************************************************
\file bash_favx2.c
\brief STB 34.101.77 (bash): bash-f AVX512 optimized
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2019.04.03
\version 2019.04.03
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#if !defined(__AVX512F__)
#error "The compiler does not support AVX512F intrinsics."
#endif

#include <intrin.h>
#include <immintrin.h>

#include "bee2/core/u64.h"
#include "bee2/crypto/bash.h"

typedef __m512i u512;

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
*******************************************************************************
*/

#define LOAD(s) _mm512_load_si512((void const *)(s))
#define LOADU(s) _mm512_loadu_si512((void const *)(s))
#define STORE(s,w) _mm512_store_si512((void *)(s), (w))
#define STOREU(s,w) _mm512_storeu_si512((void *)(s), (w))

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
позволяет сократить выражение для bash-s.
*******************************************************************************
*/

#define MF(m) ((m*7)%64)
#define M0(m) (m)
#define M1(m) M0(MF(m))
#define M2(m) M1(MF(m))
#define M3(m) M2(MF(m))
#define M4(m) M3(MF(m))
#define M5(m) M4(MF(m))
#define M6(m) M5(MF(m))
#define M7(m) M6(MF(m))

#define ML8(m) S8(M0(m),M1(m),M2(m),M3(m),M4(m),M5(m),M6(m),M7(m))
#define MR8(m) S8(64-M0(m),64-M1(m),64-M2(m),64-M3(m),64-M4(m),64-M5(m),64-M6(m),64-M7(m))

#define M1L ML8(8)
#define M1R MR8(8)
#define N1L ML8(53)
#define N1R MR8(53)
#define M2L ML8(14)
#define M2R MR8(14)
#define N2L ML8(1)
#define N2R MR8(1)

#define bashS(W0,W1,W2, U0,U1,U2) \
  do { \
    U0 = XX8(W0, W1, W2); \
    U2 = XX8(W1, SL8(N1L,U0), SR8(N1R,U0)); \
    U1 = XX8(U2, SL8(M1L,W0), SR8(M1R,W0)); \
    U2 = XX8(W2, SL8(N2L,U2), SR8(N2R,U2)); \
    U2 = XX8(U2, SL8(M2L,W2), SR8(M2R,W2));\
    W1 = XO8(U1, U0, U2); \
    W2 = XA8(U2, U0, U1); \
    W0 = XNO8(U0, U2, U1); \
  } while (0)

/*
*******************************************************************************
Тактовая перестановка без перестановки строк
*******************************************************************************
*/

#define PI0 S8(6, 3, 0, 5, 2, 7, 4, 1)
#define PI1 S8(7, 2, 1, 4, 3, 6, 5, 0)
#define PI2 S8(1, 0, 3, 2, 5, 4, 7, 6)

#define bashP(W0,W1,W2) \
  do { \
    W0 = P8(PI0, W0); \
    W1 = P8(PI1, W1); \
    W2 = P8(PI2, W2); \
  } while(0)

/*
*******************************************************************************
Такт
*******************************************************************************
*/

#define bashR0(i) \
  do { \
    bashS(W0,W1,W2, U0,U1,U2); \
    bashP(W0,W1,W2); \
    W0 = X8(W0, S8(0,0,0,0,0,0,0,C##i)); \
  } while (0)

#define bashR1(i) \
  do { \
    bashS(W1,W2,W0, U1,U2,U0); \
    bashP(W1,W2,W0); \
    W1 = X8(W1, S8(0,0,0,0,0,0,0,C##i)); \
  } while (0)

#define bashR2(i) \
  do { \
    bashS(W2,W0,W1, U2,U0,U1); \
    bashP(W2,W0,W1); \
    W2 = X8(W2, S8(0,0,0,0,0,0,0,C##i)); \
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
    bashR2(2); \
    bashR0(3); \
    bashR1(4); \
    bashR2(5); \
    bashR0(6); \
    bashR1(7); \
    bashR2(8); \
    bashR0(9); \
    bashR1(10); \
    bashR2(11); \
    bashR0(12); \
    bashR1(13); \
    bashR2(14); \
    bashR0(15); \
    bashR1(16); \
    bashR2(17); \
    bashR0(18); \
    bashR1(19); \
    bashR2(20); \
    bashR0(21); \
    bashR1(22); \
    bashR2(23); \
  } while (0)

#include <stdint.h>

/*
*******************************************************************************
Алгоритм bash-f с использованием выровненной памяти
*******************************************************************************
*/

static void bashF0_avx512(octet S[192])
{
  u512 U0, U1, U2;
  u512 W0 = LOAD(S +   0);
  u512 W1 = LOAD(S +  64);
  u512 W2 = LOAD(S + 128);

  bashF0;

  STORE(S +   0, W0);
  STORE(S +  64, W1);
  STORE(S + 128, W2);
}

/*
*******************************************************************************
Алгоритм bash-f с использованием невыровненной памяти
*******************************************************************************
*/

static void bashF0_avx512u(octet S[192])
{
  u512 U0, U1, U2;
  u512 W0 = LOADU(S +   0);
  u512 W1 = LOADU(S +  64);
  u512 W2 = LOADU(S + 128);

  bashF0;

  STOREU(S +   0, W0);
  STOREU(S +  64, W1);
  STOREU(S + 128, W2);
}

void bashF(octet block[192])
{
#if (OCTET_ORDER == BIG_ENDIAN)
  u64* s = (u64*)block;
  u64Rev2(s, 24);
#endif
  bashF0_avx512u(block);
#if (OCTET_ORDER == BIG_ENDIAN)
  u64Rev2(s, 24);
#endif
}
