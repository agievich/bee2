/*
*******************************************************************************
\file bash_f32.c
\brief STB 34.101.77 (bash): bash-f optimized for 32-bit platforms
\project bee2 [cryptographic library]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2019.04.03
\version 2019.06.27
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/u32.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bash.h"

/*
*******************************************************************************
Чередование (interleaving)

Используется техника "interleaving" -- биты в чётных и нечётных позициях
64-битного слова располагаются в двух 32-х битных словах. Это позволяет 
выполнять 64-битный сдвиг как сдвиги 32-битных слов.
*******************************************************************************
*/

/* w <- Interleaving(w) */
static void u32x2Inter(u32 w[2])
{
	register u32 t0 = u32Shuffle(w[0]);
	register u32 t1 = u32Shuffle(w[1]);
	w[0] = (t0 & 0x0000FFFF) | (t1 << 16);
	w[1] = (t0 >> 16) | (t1 & 0xFFFF0000);
	t0 = t1 = 0;
}

/* w <- Deinterleaving(w) */
static void u32x2Deinter(u32 w[2])
{
	register u32 t = (w[0] & 0x0000FFFF) | (w[1] << 16);
	w[1] = u32Deshuffle((w[0] >> 16) | (w[1] & 0xFFFF0000));
	w[0] = u32Deshuffle(t);
	t = 0;
}

/* \brief t <- RotHi(w, m) */
static void u32x2RotHi(u32 t[2], const u32 w[2], size_t m)
{
	if (m % 2 == 0)
		t[0] = u32RotHi(w[0], m / 2), t[1] = u32RotHi(w[1], m / 2);
	else if (m > 1)
		t[0] = u32RotHi(w[1], 1 + m / 2), t[1] = u32RotHi(w[0], m / 2);
	else
		t[0] = u32RotHi(w[1], 1), t[1] = w[0];
}

/*
*******************************************************************************
Bash-S
*******************************************************************************
*/

#define bashS32(w0, w1, w2, m1, n1, m2, n2)\
	u32x2RotHi(t2, w0, m1),\
	w0[0] ^= w1[0] ^ w2[0], w0[1] ^= w1[1] ^ w2[1],\
	u32x2RotHi(t1, w0, n1),\
	t1[0] ^= w1[0],\
	t1[1] ^= w1[1],\
	w1[0] = t1[0] ^ t2[0],\
	w1[1] = t1[1] ^ t2[1],\
	u32x2RotHi(t2, w2, m2),\
	u32x2RotHi(t0, t1, n2),\
	w2[0] ^= t2[0] ^ t0[0],\
	w2[1] ^= t2[1] ^ t0[1],\
	t1[0] = w0[0] | w2[0],\
	t1[1] = w0[1] | w2[1],\
	t2[0] = w0[0] & w1[0],\
	t2[1] = w0[1] & w1[1],\
	t0[0] = ~w2[0],\
	t0[1] = ~w2[1],\
	t0[0] |= w1[0],\
	t0[1] |= w1[1],\
	w0[0] ^= t0[0],\
	w0[1] ^= t0[1],\
	w1[0] ^= t1[0],\
	w1[1] ^= t1[1],\
	w2[0] ^= t2[0],\
	w2[1] ^= t2[1]

/*
*******************************************************************************
Такт без добавления тактовой константы

Макрос s реализует перемешивание слов по строкам и столбцам для текущего такта:
ячейка s(i,j) указывает на слово в i-й строке, j-м столбце.
*******************************************************************************
*/

#define bashR32(s)\
	bashS32(s(0, 0), s(1, 0), s(2, 0),  8, 53, 14,  1);\
	bashS32(s(0, 1), s(1, 1), s(2, 1), 56, 51, 34,  7);\
	bashS32(s(0, 2), s(1, 2), s(2, 2),  8, 37, 46, 49);\
	bashS32(s(0, 3), s(1, 3), s(2, 3), 56,  3,  2, 23);\
	bashS32(s(0, 4), s(1, 4), s(2, 4),  8, 21, 14, 33);\
	bashS32(s(0, 5), s(1, 5), s(2, 5), 56, 19, 34, 39);\
	bashS32(s(0, 6), s(1, 6), s(2, 6),  8,  5, 46, 17);\
	bashS32(s(0, 7), s(1, 7), s(2, 7), 56, 35,  2, 55);

/*
*******************************************************************************
Тактовые константы в "interleaved" представлении
*******************************************************************************
*/

#define c32_0_0  0x5f008465
#define c32_1_0  0x7c23af8c
#define c32_0_1  0x9db6574e
#define c32_1_1  0x884a3e9d
#define c32_0_2  0x884a3e9d
#define c32_1_2  0x4edb2ba7
#define c32_0_3  0xaf4ed365
#define c32_1_3  0xe3ef63e1
#define c32_0_4  0x027a9b23
#define c32_1_4  0xf06d151d
#define c32_0_5  0x11f8eddf
#define c32_1_5  0xa6f7313e
#define c32_0_6  0x4762c9fc
#define c32_1_6  0xaf360a40
#define c32_0_7  0xaf360a40
#define c32_1_7  0x23b164fe
#define c32_0_8  0x23b164fe
#define c32_1_8  0x579b0520
#define c32_0_9  0x579b0520
#define c32_1_9  0x11d8b27f
#define c32_0_10 0x11d8b27f
#define c32_1_10 0x2bcd8290
#define c32_0_11 0xca587a52
#define c32_1_11 0xaf262590
#define c32_0_12 0xaf262590
#define c32_1_12 0x652c3d29
#define c32_0_13 0x652c3d29
#define c32_1_13 0x579312c8
#define c32_0_14 0xb606ea0a
#define c32_1_14 0x955c623b
#define c32_0_15 0x955c623b
#define c32_1_15 0x5b037505
#define c32_0_16 0xba968dc7
#define c32_1_16 0xed644db2
#define c32_0_17 0x0cf1b570
#define c32_1_17 0xfa813a4c
#define c32_0_18 0xfa813a4c
#define c32_1_18 0x0678dab8
#define c32_0_19 0x0678dab8
#define c32_1_19 0x7d409d26
#define c32_0_20 0x7d409d26
#define c32_1_20 0x033c6d5c
#define c32_0_21 0x033c6d5c
#define c32_1_21 0x3ea04e93
#define c32_0_22 0x3ea04e93
#define c32_1_22 0x019e36ae
#define c32_0_23 0xe00bce6c
#define c32_1_23 0xb89a5be6

/*
*******************************************************************************
Добавление тактовой константы
*******************************************************************************
*/

#define bashC32(s, i)\
  s(2,7)[0] ^= c32_0_##i,\
  s(2,7)[1] ^= c32_1_##i

/*
*******************************************************************************
Тактовая подстановка
*******************************************************************************
*/

#define up(i) (((i) + 1) % 3)
#define shuffle1(i, j)\
	((i == 0) ? (j + 2 * (j & 1) + 7) % 8 : \
	((i == 1) ? (j ^ 1) : (5 * j + 6) % 8))
#define shuffle3(j)\
	(8 * (j / 8) + (j % 8 + 4) % 8)
#define s0(i, j) s[i][j]
#define s1(i, j) s0(up(i), shuffle1(i, j))
#define s2(i, j) s1(up(i), shuffle1(i, j))
#define s3(i, j) s0(   i , shuffle3(   j))
#define s4(i, j) s3(up(i), shuffle1(i, j))
#define s5(i, j) s4(up(i), shuffle1(i, j))

/*
*******************************************************************************
Bash-f (sponge-функция)
*******************************************************************************
*/

static void bashF32(u32 s[3][8][2])
{
  u32 t0[2];
  u32 t1[2];
  u32 t2[2];
  ASSERT(memIsValid(s, 192));
  bashR32(s0);  bashC32(s1, 0);
  bashR32(s1);  bashC32(s2, 1);
  bashR32(s2);  bashC32(s3, 2);
  bashR32(s3);  bashC32(s4, 3);
  bashR32(s4);  bashC32(s5, 4);
  bashR32(s5);  bashC32(s0, 5);
  bashR32(s0);  bashC32(s1, 6);
  bashR32(s1);  bashC32(s2, 7);
  bashR32(s2);  bashC32(s3, 8);
  bashR32(s3);  bashC32(s4, 9);
  bashR32(s4);  bashC32(s5, 10);
  bashR32(s5);  bashC32(s0, 11);
  bashR32(s0);  bashC32(s1, 12);
  bashR32(s1);  bashC32(s2, 13);
  bashR32(s2);  bashC32(s3, 14);
  bashR32(s3);  bashC32(s4, 15);
  bashR32(s4);  bashC32(s5, 16);
  bashR32(s5);  bashC32(s0, 17);
  bashR32(s0);  bashC32(s1, 18);
  bashR32(s1);  bashC32(s2, 19);
  bashR32(s2);  bashC32(s3, 20);
  bashR32(s3);  bashC32(s4, 21);
  bashR32(s4);  bashC32(s5, 22);
  bashR32(s5);  bashC32(s0, 23);
  t0[0] = t1[0] = t2[0] = 0;
  t0[1] = t1[1] = t2[1] = 0;
}

void bashF(octet block[192])
{
	size_t i, j;
	u32 (*s)[3][8][2] = (u32(*)[3][8][2])block;
#if (OCTET_ORDER == BIG_ENDIAN)
	u32Rev2((u32*)s, 48);
#endif
	for (i = 0; i < 3; ++i)
	for (j = 0; j < 8; ++j)
		u32x2Inter((*s)[i][j]);
	bashF32(*s);
	for (i = 0; i < 3; ++i)
	for (j = 0; j < 8; ++j)
		u32x2Deinter((*s)[i][j]);
#if (OCTET_ORDER == BIG_ENDIAN)
	u32Rev2((u32*)s, 48);
#endif
}
