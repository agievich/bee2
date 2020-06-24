/*
*******************************************************************************
\file bash_prg.c
\brief STB 34.101.77 (bash): programmable algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2018.10.30
\version 2020.06.24
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bash.h"

/*
*******************************************************************************
Программируемые алгоритмы

\remark В bash_prg_st::s хранится состояние автомата. Состояние как строка 
октетов состоит из двух частей:
1) буфер (первые buf_len октетов);
2) память (все остальное).

Данные загружаются в буфер и выгружаются из буфера блоками по buf_len октетов.

В бесключевом режиме память содержит 2dl битов, в ключевом -- (l + dl/2) битов.
Эти факты используются в функции bashPrgIsKeymode() для проверки того, что
автомат находится в ключевом режиме.

Первый бит памяти является контрольным -- он инвертируется в bashPrgCommit().

Длина buf_len в зависимости от параметров и режима:

 l  | d | key | keyless
-----------------------
128 | 1 | 168 | 160
128 | 2 | 160 | 128
192 | 1 | 156 | 144
192 | 2 | 144 |  96 
256 | 1 | 144 | 128
256 | 2 | 128 |  64

6-битовые коды NULL, KEY, DATA, TEXT, OUT дополнены (справа) парой битов 01
и объявлены как BASH_PRG_XXX.
*******************************************************************************
*/

#define BASH_PRG_NULL		0x01	/* 000000 01 */
#define BASH_PRG_KEY		0x05	/* 000001 01 */
#define BASH_PRG_DATA		0x09	/* 000010 01 */
#define BASH_PRG_TEXT		0x0D	/* 000011 01 */
#define BASH_PRG_OUT		0x11	/* 000100 01 */

typedef struct {
	size_t l;			/*< уровень стойкости */
	size_t d;			/*< емкость */
	octet s[192];		/*< состояние */
	size_t buf_len;		/*< длина буфера */
	size_t pos;			/*< позиция в буфере */
	octet t[192];		/*< копия состояния (для ratchet) */
	octet stack[];		/*< [bashF_deep()] стек bashF */
} bash_prg_st;

size_t bashPrg_keep()
{
	return sizeof(bash_prg_st) + bashF_deep();
}

/*
*******************************************************************************
Вспомогательные функции
*******************************************************************************
*/

static bool_t bashPrgIsKeymode(const void* state)
{
	const bash_prg_st* st = (const bash_prg_st*)state;
	ASSERT(memIsValid(st, bashPrg_keep()));
	// (192 - buf_len) ==? (l + d * l / 2) / 8
	return 16 * (192 - st->buf_len) == st->l * (2 + st->d);
}

/*
*******************************************************************************
Commit: завершить предыдущую команду и начать новую с кодом code
*******************************************************************************
*/

static void bashPrgCommit(octet code, void* state)
{
	bash_prg_st* st = (bash_prg_st*)state;
	ASSERT(memIsValid(st, bashPrg_keep()));
	ASSERT(st->pos < st->buf_len);
	// учесть code
	st->s[st->pos] ^= code;
	// инвертировать контрольный бит
	st->s[st->buf_len] ^= 0x80;
	// применить sponge-функцию
	bashF(st->s, st->stack);
	// сбросить pos
	st->pos = 0;
}

/*
*******************************************************************************
Start: инициализировать
*******************************************************************************
*/

void bashPrgStart(void* state, size_t l, size_t d, const octet ann[],
	size_t ann_len, const octet key[], size_t key_len)
{
	bash_prg_st* st = (bash_prg_st*)state;
	ASSERT(memIsValid(st, bashPrg_keep()));
	ASSERT(l == 128 || l == 192 || l == 256);
	ASSERT(d == 1 || d == 2);
	ASSERT(ann_len % 4 == 0 && ann_len <= 60);
	ASSERT(key_len % 4 == 0 && key_len <= 60);
	ASSERT(key_len == 0 || key_len >= l / 8);
	ASSERT(memIsDisjoint2(st, bashPrg_keep(), ann, ann_len));
	ASSERT(memIsDisjoint2(st, bashPrg_keep(), key, key_len));
	// pos <- 8 + |ann| + |key|
	st->pos = 1 + ann_len + key_len;
	// s[0..pos) <- <|ann|/2 + |key|/32>_8 || ann || key
	st->s[0] = (octet)(ann_len * 4 + key_len / 4);
	memCopy(st->s + 1, ann, ann_len); 
	memCopy(st->s + 1 + ann_len, key, key_len);
	// s[pos..) <- 0
	memSetZero(st->s + st->pos, 192 - st->pos);
	// s[1472..) <- <l / 4 + d>_{64}
	st->s[192 - 8] = (octet)(l / 4  + d);
	// длина буфера
	st->buf_len = key_len ? (192 - l * (2 + d) / 16) : (192 - d * l / 4);
	// сохранить параметры
	st->l = l, st->d = d;
}

/*
*******************************************************************************
Restart: повторно инициализировать
*******************************************************************************
*/

void bashPrgRestart(const octet ann[], size_t ann_len, 
	const octet key[], size_t key_len, void* state)
{
	bash_prg_st* st = (bash_prg_st*)state;
	ASSERT(memIsValid(st, bashPrg_keep()));
	ASSERT(ann_len % 4 == 0 && ann_len <= 60);
	ASSERT(key_len % 4 == 0 && key_len <= 60);
	ASSERT(key_len == 0 || key_len >= st->l / 8);
	ASSERT(memIsDisjoint2(st, bashPrg_keep(), ann, ann_len));
	ASSERT(memIsDisjoint2(st, bashPrg_keep(), key, key_len));
	// вводится ключ?
	if (key_len)
	{
		bashPrgCommit(BASH_PRG_KEY, state);
		// перейти в ключевой режим (если еще не в нем)
		st->buf_len = 192 - st->l * (2 + st->d) / 16;
	}
	else
		bashPrgCommit(BASH_PRG_NULL, state);
	// pos <- 8 + |ann| + |key|
	st->pos = 1 + ann_len + key_len;
	// s[0..pos) <- s[0..pos) ^ <|ann|/2 + |key|/32>_8  || ann || key
	st->s[0] ^= (octet)(ann_len * 4 + key_len / 4);
	memXor2(st->s + 1, ann, ann_len); 
	memXor2(st->s + 1 + ann_len, key, key_len);
}

/*
*******************************************************************************
Absorb: загрузить
*******************************************************************************
*/

void bashPrgAbsorbStart(void* state)
{
	bashPrgCommit(BASH_PRG_DATA, state);
}

void bashPrgAbsorbStep(const void* buf, size_t count, void* state)
{
	bash_prg_st* st = (bash_prg_st*)state;
	ASSERT(memIsDisjoint2(st, bashPrg_keep(), buf, count));
	// не накопился полный буфер?
	if (count < st->buf_len - st->pos)
	{
		memXor2(st->s + st->pos, buf, count);
		st->pos += count;
		return;
	}
	// новый полный буфер
	memXor2(st->s + st->pos, buf, st->buf_len - st->pos);
	buf = (const octet*)buf + st->buf_len - st->pos;
	count -= st->buf_len - st->pos;
	bashF(st->s, st->stack);
	// цикл по полным блокам
	while (count >= st->buf_len)
	{
		memXor2(st->s, buf, st->buf_len);
		buf = (const octet*)buf + st->buf_len;
		count -= st->buf_len;
		bashF(st->s, st->stack);
	}
	// неполный блок?
	if (st->pos = count)
		memXor2(st->s, buf, count);
}

void bashPrgAbsorb(const void* buf, size_t count, void* state)
{
	bashPrgAbsorbStart(state);
	bashPrgAbsorbStep(buf, count, state);
}

/*
*******************************************************************************
Squeeze: выгрузить
*******************************************************************************
*/

void bashPrgSqueezeStart(void* state)
{
	bashPrgCommit(BASH_PRG_OUT, state);
}

void bashPrgSqueezeStep(void* buf, size_t count, void* state)
{
	bash_prg_st* st = (bash_prg_st*)state;
	ASSERT(memIsDisjoint2(st, bashPrg_keep(), buf, count));
	// остатка буфера достаточно?
	if (count < st->buf_len - st->pos)
	{
		memCopy(buf, st->s + st->pos, count);
		st->pos += count;
		return;
	}
	// новый буфер
	memCopy(buf, st->s + st->pos, st->buf_len - st->pos);
	buf = (octet*)buf + st->buf_len - st->pos;
	count -= st->buf_len - st->pos;
	bashF(st->s, st->stack);
	// цикл по полным блокам
	while (count >= st->buf_len)
	{
		memCopy(buf, st->s, st->buf_len);
		buf = (octet*)buf + st->buf_len;
		count -= st->buf_len;
		bashF(st->s, st->stack);
	}
	// неполный блок
	if (st->pos = count)
		memCopy(buf, st->s, count);
}

void bashPrgSqueeze(void* buf, size_t count, void* state)
{
	bashPrgSqueezeStart(state);
	bashPrgSqueezeStep(buf, count, state);
}

/*
*******************************************************************************
Encr: зашифровать
*******************************************************************************
*/

void bashPrgEncrStart(void* state)
{
	ASSERT(bashPrgIsKeymode(state));
	bashPrgCommit(BASH_PRG_TEXT, state);
}

void bashPrgEncrStep(void* buf, size_t count, void* state)
{
	bash_prg_st* st = (bash_prg_st*)state;
	ASSERT(memIsDisjoint2(st, bashPrg_keep(), buf, count));
	// остатка буфера достаточно?
	if (count < st->buf_len - st->pos)
	{
		memXor2(st->s + st->pos, buf, count);
		memCopy(buf, st->s + st->pos, count);
		st->pos += count;
		return;
	}
	// новый буфер
	memXor2(st->s + st->pos, buf, st->buf_len - st->pos);
	memCopy(buf, st->s + st->pos, st->buf_len - st->pos);
	buf = (octet*)buf + st->buf_len - st->pos;
	count -= st->buf_len - st->pos;
	bashF(st->s, st->stack);
	// цикл по полным блокам
	while (count >= st->buf_len)
	{
		memXor2(st->s, buf, st->buf_len);
		memCopy(buf, st->s, st->buf_len);
		buf = (octet*)buf + st->buf_len;
		count -= st->buf_len;
		bashF(st->s, st->stack);
	}
	// неполный блок
	if (st->pos = count)
	{
		memXor2(st->s, buf, count);
		memCopy(buf, st->s, count);
	}
}

void bashPrgEncr(void* buf, size_t count, void* state)
{
	bashPrgEncrStart(state);
	bashPrgEncrStep(buf, count, state);
}

/*
*******************************************************************************
Decr: расшифровать
*******************************************************************************
*/

void bashPrgDecrStart(void* state)
{
	ASSERT(bashPrgIsKeymode(state));
	bashPrgCommit(BASH_PRG_TEXT, state);
}

void bashPrgDecrStep(void* buf, size_t count, void* state)
{
	bash_prg_st* st = (bash_prg_st*)state;
	ASSERT(memIsDisjoint2(st, bashPrg_keep(), buf, count));
	// остатка буфера достаточно?
	if (count < st->buf_len - st->pos)
	{
		memXor2(buf, st->s + st->pos, count);
		memXor2(st->s + st->pos, buf, count);
		st->pos += count;
		return;
	}
	// новый буфер
	memXor2(buf, st->s + st->pos, st->buf_len - st->pos);
	memXor2(st->s + st->pos, buf, st->buf_len - st->pos);
	buf = (octet*)buf + st->buf_len - st->pos;
	count -= st->buf_len - st->pos;
	bashF(st->s, st->stack);
	// цикл по полным блокам
	while (count >= st->buf_len)
	{
		memXor2(buf, st->s, st->buf_len);
		memXor2(st->s, buf, st->buf_len);
		buf = (octet*)buf + st->buf_len;
		count -= st->buf_len;
		bashF(st->s, st->stack);
	}
	// неполный блок
	if (st->pos = count)
	{
		memXor2(buf, st->s, count);
		memXor2(st->s, buf, count);
	}
}

void bashPrgDecr(void* buf, size_t count, void* state)
{
	bashPrgDecrStart(state);
	bashPrgDecrStep(buf, count, state);
}

/*
*******************************************************************************
Ratchet: необратимо изменить
*******************************************************************************
*/

void bashPrgRatchet(void* state)
{
	bash_prg_st* st = (bash_prg_st*)state;
	ASSERT(memIsValid(st, bashPrg_keep()));
	// завершить предыдущую команду
	bashPrgCommit(BASH_PRG_NULL, state);
	// необратимо изменить
	memCopy(st->t, st->s, 192);
	bashF(st->s, st->stack);
	memXor2(st->s, st->t, 192);
}
