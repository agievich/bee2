/*
*******************************************************************************
\file bash_f32.c
\brief STB 34.101.77 (bash): bash-f optimized for 32-bit platforms
\project bee2 [cryptographic library]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2019.04.03
\version 2019.07.09
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
	register u32 t0 = u32Deshuffle(w[0]);
	register u32 t1 = u32Deshuffle(w[1]);
	w[0] = (t0 & 0x0000FFFF) | (t1 << 16);
	w[1] = (t0 >> 16) | (t1 & 0xFFFF0000);
	t0 = t1 = 0;
}

/* w <- Deinterleaving(w) */
static void u32x2Deinter(u32 w[2])
{
	register u32 t = (w[0] & 0x0000FFFF) | (w[1] << 16);
	w[1] = u32Shuffle((w[0] >> 16) | (w[1] & 0xFFFF0000));
	w[0] = u32Shuffle(t);
	t = 0;
}

/* t <- RotHi(w, m) */
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
Алгоритм bash-s
*******************************************************************************
*/

#define bashS(w0, w1, w2, m1, n1, m2, n2)\
	u32x2RotHi(t2, w0, m1),\
	w0[0] ^= w1[0] ^ w2[0],\
	w0[1] ^= w1[1] ^ w2[1],\
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

#define bashR(s)\
	bashS(s(0, 0), s(1, 0), s(2, 0),  8, 53, 14,  1);\
	bashS(s(0, 1), s(1, 1), s(2, 1), 56, 51, 34,  7);\
	bashS(s(0, 2), s(1, 2), s(2, 2),  8, 37, 46, 49);\
	bashS(s(0, 3), s(1, 3), s(2, 3), 56,  3,  2, 23);\
	bashS(s(0, 4), s(1, 4), s(2, 4),  8, 21, 14, 33);\
	bashS(s(0, 5), s(1, 5), s(2, 5), 56, 19, 34, 39);\
	bashS(s(0, 6), s(1, 6), s(2, 6),  8,  5, 46, 17);\
	bashS(s(0, 7), s(1, 7), s(2, 7), 56, 35,  2, 55);

/*
*******************************************************************************
Тактовые константы в "interleaved" представлении

Схема расчета (ci -- стандартные константы, см. bash_f64.c):
\code
	ci_0 = (u32)u64Deshuffle(ci);
	ci_1 = (u32)(u64Deshuffle(ci) >> 32);
\endcode
*******************************************************************************
*/

#define c1_0  0x5F008465
#define c1_1  0x7C23AF8C
#define c2_0  0x9DB6574E
#define c2_1  0x884A3E9D
#define c3_0  0x884A3E9D
#define c3_1  0x4EDB2BA7
#define c4_0  0xAF4ED365
#define c4_1  0xE3EF63E1
#define c5_0  0x027A9B23
#define c5_1  0xF06D151D
#define c6_0  0x11F8EDDF
#define c6_1  0xA6F7313E
#define c7_0  0x4762C9FC
#define c7_1  0xAF360A40
#define c8_0  0xAF360A40
#define c8_1  0x23B164FE
#define c9_0  0x23B164FE
#define c9_1  0x579B0520
#define c10_0 0x579B0520
#define c10_1 0x11D8B27F
#define c11_0 0x11D8B27F
#define c11_1 0x2BCD8290
#define c12_0 0xCA587A52
#define c12_1 0xAF262590
#define c13_0 0xAF262590
#define c13_1 0x652C3D29
#define c14_0 0x652C3D29
#define c14_1 0x579312C8
#define c15_0 0xB606EA0A
#define c15_1 0x955C623B
#define c16_0 0x955C623B
#define c16_1 0x5B037505
#define c17_0 0xBA968DC7
#define c17_1 0xED644DB2
#define c18_0 0x0CF1B570
#define c18_1 0xFA813A4C
#define c19_1 0x0678DAB8
#define c19_0 0xFA813A4C
#define c20_0 0x0678DAB8
#define c20_1 0x7D409D26
#define c21_0 0x7D409D26
#define c21_1 0x033C6D5C
#define c22_0 0x033C6D5C
#define c22_1 0x3EA04E93
#define c23_0 0x3EA04E93
#define c23_1 0x019E36AE
#define c24_0 0xE00BCE6C
#define c24_1 0xB89A5BE6

/*
*******************************************************************************
Добавление тактовой константы
*******************************************************************************
*/

#define bashC(s, i)\
	s(2,7)[0] ^= c##i##_0,\
	s(2,7)[1] ^= c##i##_1

/*
*******************************************************************************
Навигация по словам состояния s (u64[3][8] = u32[3][8][2]):
	sk(i, j) = P^k(s)[i][j]
*******************************************************************************
*/

#define up(i) (((i) + 1) % 3)
#define p1(i, j)\
	((i == 0) ? (j + 2 * (j & 1) + 7) % 8 : \
	((i == 1) ? (j ^ 1) : (5 * j + 6) % 8))
#define p3(j)\
	(8 * (j / 8) + (j % 8 + 4) % 8)
#define s0(i, j) s[i][j]
#define s1(i, j) s0(up(i), p1(i, j))
#define s2(i, j) s1(up(i), p1(i, j))
#define s3(i, j) s0(   i , p3(   j))
#define s4(i, j) s3(up(i), p1(i, j))
#define s5(i, j) s4(up(i), p1(i, j))

/*
*******************************************************************************
Алгоритм bash-f (sponge-функция)

\todo Если объявить
\code
	u32 t0[2];
	u32 t1[2];
	u32 t2[2];
\endcode
то скорость на 64-разрядных платформах с принудительным сбросом на BASH_32
падает примерно в 1.5 раза. Разобраться.
*******************************************************************************
*/

static void bashF0(u32 s[3][8][2], void* stack)
{
	u32* t0 = (u32*)stack;
	u32* t1 = t0 + 2;
	u32* t2 = t1 + 2;

	bashR(s0);  bashC(s1, 1);
	bashR(s1);  bashC(s2, 2);
	bashR(s2);  bashC(s3, 3);
	bashR(s3);  bashC(s4, 4);
	bashR(s4);  bashC(s5, 5);
	bashR(s5);  bashC(s0, 6);
	bashR(s0);  bashC(s1, 7);
	bashR(s1);  bashC(s2, 8);
	bashR(s2);  bashC(s3, 9);
	bashR(s3);  bashC(s4, 10);
	bashR(s4);  bashC(s5, 11);
	bashR(s5);  bashC(s0, 12);
	bashR(s0);  bashC(s1, 13);
	bashR(s1);  bashC(s2, 14);
	bashR(s2);  bashC(s3, 15);
	bashR(s3);  bashC(s4, 16);
	bashR(s4);  bashC(s5, 17);
	bashR(s5);  bashC(s0, 18);
	bashR(s0);  bashC(s1, 19);
	bashR(s1);  bashC(s2, 20);
	bashR(s2);  bashC(s3, 21);
	bashR(s3);  bashC(s4, 22);
	bashR(s4);  bashC(s5, 23);
	bashR(s5);  bashC(s0, 24);
}

void bashF(octet block[192], void* stack)
{
	size_t i, j;
	u32 (*s)[3][8][2] = (u32(*)[3][8][2])block;
	ASSERT(memIsDisjoint2(block, 192, stack, bashF_deep()));
#if (OCTET_ORDER == BIG_ENDIAN)
	u32Rev2((u32*)s, 48);
#endif
	for (i = 0; i < 3; ++i)
	for (j = 0; j < 8; ++j)
		u32x2Inter((*s)[i][j]);
	bashF0(*s, stack);
	for (i = 0; i < 3; ++i)
	for (j = 0; j < 8; ++j)
		u32x2Deinter((*s)[i][j]);
#if (OCTET_ORDER == BIG_ENDIAN)
	u32Rev2((u32*)s, 48);
#endif
}

size_t bashF_deep()
{
	return sizeof(u32) * 2 * 3;
}
