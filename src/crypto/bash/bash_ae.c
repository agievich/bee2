/*
*******************************************************************************
\file bash_ae.c
\brief STB 34.101.77 (bash): authenticated encryption
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2018.10.30
\version 2019.07.09
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/util.h"
#include "bee2/crypto/bash.h"

/*
*******************************************************************************
Аутентифицированное шифрование

\remark В bash_ae_st::s хранится состояние автомата. Состояние как строка 
октетов состоит из трех последовательных частей:
1) буфер (block_len = 192 - l / 4 октетов);
2) октет управление (смещение block_len);
3) память (все остальное).

\remark Макросы bashAECtrlX управляют частями октета управления. Эти части:
A) признак полного (1) / неполного (0) блока (1 бит);
B) признак промежуточного (1) / завершающего (0) блока (1 бит);
C) тип текущего блока (3 бита);
D) тип следующего блока (3 бита).
Обработка блока отложенная, поэтому тип следующего блока будет известен 
в момент обработки.

\remark В bashAEStart() состояние заполнено так, как будто сделаны вызовы
	bashAECtrlA(s, 0), bashAECtrlB(s, 0), bashAECtrlC(s, BASH_KEY);
*******************************************************************************
*/

typedef struct {
	octet s[192];		/*< состояние */
	size_t block_len;	/*< длина блока */
	size_t filled;		/*< загружено/выгружено октетов в блок/из блока */
	octet code;			/*< код текущего типа данных */
	octet stack[];		/*< [[bashF_deep()] стек bashF */
} bash_ae_st;

static void bashAECtrl(bash_ae_st* s, octet mask, octet val)
{
	s->s[s->block_len] &= mask;
	s->s[s->block_len] |= val;
}

#define bashAECtrlA(s, a) bashAECtrl(s, 0x7F, (a) << 7)
#define bashAECtrlB(s, b) bashAECtrl(s, 0xBF, (b) << 6)
#define bashAECtrlC(s, c) bashAECtrl(s, 0xC7, (c) << 3)
#define bashAECtrlD(s, d) bashAECtrl(s, 0xF8, (d) << 0)

size_t bashAE_keep()
{
	return sizeof(bash_ae_st) + bashF_deep();
}

void bashAEStart(void* state, const octet key[], size_t key_len, 
	const octet iv[], size_t iv_len)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(key_len == 16 || key_len == 24 || key_len == 32);
	ASSERT(iv_len <= key_len * 2);
	ASSERT(memIsDisjoint2(s, bashAE_keep(), key, key_len));
	ASSERT(memIsDisjoint2(s, bashAE_keep(), iv, iv_len));
	// s[0..1472 = 184 * 8) <- key || iv || 10...0
	memCopy(s->s, key, key_len); 
	memCopy(s->s + key_len, iv, iv_len);
	memSetZero(s->s + key_len + iv_len, 192 - key_len - iv_len);
	s->s[key_len + iv_len] = 0x80;
	// s[1472..) <- <l / 4 + 1>_{64}
	s->s[192 - 8] = (octet)(key_len * 2 + 1);
	// длина блока
	s->block_len = 192 - key_len * 2;
	// накопленные данные 
	s->filled = key_len + iv_len;
	// запомнить код
	s->code = BASH_AE_KEY;
}

/*
*******************************************************************************
Absorb (Загрузка)
*******************************************************************************
*/

void bashAEAbsorbStart(octet code, void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(code == BASH_AE_KEY || code == BASH_AE_DATA);
	ASSERT(memIsValid(s, bashAE_keep()));
	// обработать отложенный блок
	bashAECtrlA(s, s->filled == s->block_len); /* полный? */
	bashAECtrlB(s, 0); /* заключительный */
	bashAECtrlC(s, s->code);
	bashAECtrlD(s, code);
	bashF(s->s, s->stack);
	s->filled = 0;
	// запомнить код
	s->code = code;
}

void bashAEAbsorbStep(const void* buf, size_t count, void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, bashAE_keep()));
	// не накопится на полный блок?
	if (count < s->block_len - s->filled)
	{
		memCopy(s->s + s->filled, buf, count);
		s->filled += count;
		return;
	}
	// новый полный блок
	memCopy(s->s + s->filled, buf, s->block_len - s->filled);
	buf = (const octet*)buf + s->block_len - s->filled;
	count -= s->block_len - s->filled;
	s->filled = s->block_len;
	// цикл по полным блокам
	while (count >= s->block_len)
	{
		// обработать отложенный блок
		bashAECtrlA(s, 1); /* полный */
		bashAECtrlB(s, 1); /* промежуточный */
		bashAECtrlC(s, s->code);
		bashAECtrlD(s, s->code);
		bashF(s->s, s->stack);
		// новый полный блок
		memCopy(s->s, buf, s->block_len);
		buf = (const octet*)buf + s->block_len;
		count -= s->block_len;
	}
	// неполный блок?
	if (count)
		memCopy(s->s, buf, s->filled = count);
}

void bashAEAbsorbStop(void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(memIsValid(s, bashAE_keep()));
	// подготовить отложенный блок к завершению текущей операции
	memSetZero(s->s + s->filled, s->block_len - s->filled);
	// можем попасть в октет управления, но это не важно
	s->s[s->filled] = 0x80;
}

void bashAEAbsorb(octet code, const void* buf, size_t count, void* state)
{
	bashAEAbsorbStart(code, state);
	bashAEAbsorbStep(buf, count, state);
	bashAEAbsorbStop(state);
}

/*
*******************************************************************************
Squeeze (Выгрузка)
*******************************************************************************
*/

void bashAESqueezeStart(octet code, void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(code == BASH_AE_PRN || code == BASH_AE_MAC);
	ASSERT(memIsValid(s, bashAE_keep()));
	// обработать отложенный блок
	bashAECtrlA(s, s->filled == s->block_len); /* полный? */
	bashAECtrlB(s, 0); /* заключительный */ 
	bashAECtrlC(s, s->code);
	bashAECtrlD(s, code);
	bashF(s->s, s->stack);
	s->filled = 0;
	// запомнить код
	s->code = code;
}

void bashAESqueezeStep(void* buf, size_t count, void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, bashAE_keep()));
	// есть остаток в буфере?
	if (s->filled < s->block_len)
	{
		if (count <= s->block_len - s->filled)
		{
			memCopy(buf, s->s + s->filled, count);
			s->filled += count;
			return;
		}
		// новый входной полный блок
		memCopy(buf, s->s + s->filled, s->block_len - s->filled);
		buf = (octet*)buf + s->block_len - s->filled;
		count -= s->block_len - s->filled;
		s->filled = s->block_len;
	}
	// цикл по полным блокам
	while (count >= s->block_len)
	{
		// обработать отложенный блок
		bashAECtrlA(s, 0); /* всегда 0 */
		bashAECtrlB(s, 1); /* промежуточный */
		bashAECtrlC(s, s->code);
		bashAECtrlD(s, s->code);
		bashF(s->s, s->stack);
		// новый полный блок
		memCopy(buf, s->s, s->block_len);
		buf = (octet*)buf + s->block_len;
		count -= s->block_len;
	}
	// еще?
	if (count)
	{
		// обработать отложенный блок
		bashAECtrlA(s, 0); /* всегда 0 */
		bashAECtrlB(s, 1); /* промежуточный */
		bashAECtrlC(s, s->code);
		bashAECtrlD(s, s->code);
		bashF(s->s, s->stack);
		// новый полный блок
		memCopy(buf, s->s, s->filled = count);
	}
}

void bashAESqueezeStop(void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(memIsValid(s, bashAE_keep()));
	// чтобы считали, что был неполный блок
	s->filled = 0;
}

void bashAESqueeze(octet code, void* buf, size_t count, void* state)
{
	bashAESqueezeStart(code, state);
	bashAESqueezeStep(buf, count, state);
	bashAESqueezeStop(state);
}

/*
*******************************************************************************
Encr (Зашифрование)
*******************************************************************************
*/

void bashAEEncrStart(void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(memIsValid(s, bashAE_keep()));
	// обработать отложенный блок
	bashAECtrlA(s, s->filled == s->block_len); /* полный? */
	bashAECtrlB(s, 0); /* заключительный */
	bashAECtrlC(s, s->code);
	bashAECtrlD(s, BASH_AE_TEXT);
	bashF(s->s, s->stack);
	s->filled = 0;
	// запомнить код
	s->code = BASH_AE_TEXT;
}

void bashAEEncrStep(void* buf, size_t count, void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, bashAE_keep()));
	// есть остаток в буфере?
	if (s->filled < s->block_len)
	{
		if (count <= s->block_len - s->filled)
		{
			memXor2(buf, s->s + s->filled, count);
			memXor2(s->s + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memXor2(buf, s->s + s->filled, s->block_len - s->filled);
		memXor2(s->s + s->filled, buf, s->block_len - s->filled);
		buf = (octet*)buf + s->block_len - s->filled;
		count -= s->block_len - s->filled;
		s->filled = s->block_len;
	}
	// цикл по полным блокам
	while (count >= s->block_len)
	{
		// обработать отложенный блок
		bashAECtrlA(s, 1); /* полный */
		bashAECtrlB(s, 1); /* промежуточный */
		bashAECtrlC(s, s->code);
		bashAECtrlD(s, s->code);
		bashF(s->s, s->stack);
		// новый полный блок
		memXor2(buf, s->s, s->block_len);
		memXor2(s->s, buf, s->block_len);
		buf = (octet*)buf + s->block_len;
		count -= s->block_len;
	}
	// еще?
	if (count)
	{
		// обработать отложенный блок
		bashAECtrlA(s, 1); /* полный */
		bashAECtrlB(s, 1); /* промежуточный */
		bashAECtrlC(s, s->code);
		bashAECtrlD(s, s->code);
		bashF(s->s, s->stack);
		// новый полный блок
		memXor2(buf, s->s, count);
		memXor2(s->s, buf, s->filled = count);
	}
}

void bashAEEncrStop(void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(memIsValid(s, bashAE_keep()));
	// подготовить отложенный блок к завершению текущей операции
	memSetZero(s->s + s->filled, s->block_len - s->filled);
	// можем попасть в октет управления, но это не важно
	s->s[s->filled] = 0x80;
}

void bashAEEncr(void* buf, size_t count, void* state)
{
	bashAEEncrStart(state);
	bashAEEncrStep(buf, count, state);
	bashAEEncrStop(state);
}

/*
*******************************************************************************
Decr (Расшифрование)
*******************************************************************************
*/

void bashAEDecrStart(void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(memIsValid(s, bashAE_keep()));
	// обработать отложенный блок
	bashAECtrlA(s, s->filled == s->block_len); /* полный? */
	bashAECtrlB(s, 0); /* заключительный */
	bashAECtrlC(s, s->code);
	bashAECtrlD(s, BASH_AE_TEXT);
	bashF(s->s, s->stack);
	s->filled = 0;
	// запомнить код
	s->code = BASH_AE_TEXT;
}

void bashAEDecrStep(void* buf, size_t count, void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, bashAE_keep()));
	// есть остаток в буфере?
	if (s->filled < s->block_len)
	{
		if (count <= s->block_len - s->filled)
		{
			memXor2(buf, s->s + s->filled, count);
			memCopy(s->s + s->filled, buf, count);
			s->filled += count;
			return;
		}
		memXor2(buf, s->s + s->filled, s->block_len - s->filled);
		memCopy(s->s + s->filled, buf, s->block_len - s->filled);
		buf = (octet*)buf + s->block_len - s->filled;
		count -= s->block_len - s->filled;
		s->filled = s->block_len;
	}
	// цикл по полным блокам
	while (count >= s->block_len)
	{
		// обработать отложенный блок
		bashAECtrlA(s, 1); /* полный */
		bashAECtrlB(s, 1); /* промежуточный */
		bashAECtrlC(s, s->code);
		bashAECtrlD(s, s->code);
		bashF(s->s, s->stack);
		// новый полный блок
		memXor2(buf, s->s, s->block_len);
		memCopy(s->s, buf, s->block_len);
		buf = (octet*)buf + s->block_len;
		count -= s->block_len;
	}
	// еще?
	if (count)
	{
		// обработать отложенный блок
		bashAECtrlA(s, 1); /* полный */
		bashAECtrlB(s, 1); /* промежуточный */
		bashAECtrlC(s, s->code);
		bashAECtrlD(s, s->code);
		bashF(s->s, s->stack);
		// новый полный блок
		memXor2(buf, s->s, count);
		memCopy(s->s, buf, s->filled = count);
	}
}

void bashAEDecrStop(void* state)
{
	bash_ae_st* s = (bash_ae_st*)state;
	ASSERT(memIsValid(s, bashAE_keep()));
	// подготовить отложенный блок к завершению текущей операции
	memSetZero(s->s + s->filled, s->block_len - s->filled);
	// можем попасть в октет управления, но это не важно
	s->s[s->filled] = 0x80;
}

void bashAEDecr(void* buf, size_t count, void* state)
{
	bashAEDecrStart(state);
	bashAEDecrStep(buf, count, state);
	bashAEDecrStop(state);
}
