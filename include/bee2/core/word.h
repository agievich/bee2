/*
*******************************************************************************
\file word.h
\brief Machine words
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.07.18
\version 2019.06.27
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file word.h
\brief Машинные слова
*******************************************************************************
*/

#ifndef __BEE2_WORD_H
#define __BEE2_WORD_H

#include "bee2/defs.h"
#include "bee2/core/safe.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file word.h

Реализованы быстрые манипуляции с машинными словами.

\remark Манипуляции с массивами машинных слов реализованы в модуле ww.
*******************************************************************************
*/

#define WORD_0 ((word)0)
#define WORD_1 ((word)1)
#define WORD_MAX ((word)(WORD_0 - WORD_1))

#define WORD_BIT_POS(pos) (WORD_1 << (pos))
#define WORD_BIT_HI WORD_BIT_POS(B_PER_W - 1)
#define WORD_BIT_HALF WORD_BIT_POS(B_PER_W / 2)

#if (B_PER_W == 16)
	#include "bee2/core/u16.h"
	#define wordRotHi u16RotHi
	#define wordRotLo u16RotLo
	#define wordRev u16Rev
	#define wordWeight u16Weight
	#define wordParity u16Parity
	#define wordCTZ u16CTZ
	#define wordCLZ u16CLZ
	#ifdef SAFE_FAST
		#define wordCTZ_safe u16CTZ_safe
		#define wordCLZ_safe u16CLZ_safe
	#else
		#define wordCTZ_fast u16CTZ_fast
		#define wordCLZ_fast u16CLZ_fast
	#endif
	#define	wordShuffle u16Shuffle
	#define	wordDeshuffle u16Deshuffle
	#define	wordNegInv u16NegInv
#elif (B_PER_W == 32)
	#include "bee2/core/u32.h"
	#define wordRotHi u32RotHi
	#define wordRotLo u32RotLo
	#define wordRev u32Rev
	#define wordWeight u32Weight
	#define wordParity u32Parity
	#define wordCTZ u32CTZ
	#define wordCLZ u32CLZ
	#ifdef SAFE_FAST
		#define wordCTZ_safe u32CTZ_safe
		#define wordCLZ_safe u32CLZ_safe
	#else
		#define wordCTZ_fast u32CTZ_fast
		#define wordCLZ_fast u32CLZ_fast
	#endif
	#define	wordShuffle u32Shuffle
	#define	wordDeshuffle u32Deshuffle
	#define	wordNegInv u32NegInv
#elif (B_PER_W == 64)
	#include "bee2/core/u64.h"
	#define wordRotHi u64RotHi
	#define wordRotLo u64RotLo
	#define wordRev u64Rev
	#define wordWeight u64Weight
	#define wordParity u64Parity
	#define wordCTZ u64CTZ
	#define wordCLZ u64CLZ
	#ifdef SAFE_FAST
		#define wordCTZ_safe u64CTZ_safe
		#define wordCLZ_safe u64CLZ_safe
	#else
		#define wordCTZ_fast u64CTZ_fast
		#define wordCLZ_fast u64CLZ_fast
	#endif
	#define	wordShuffle u64Shuffle
	#define	wordDeshuffle u64Deshuffle
	#define	wordNegInv u64NegInv
#else
	#error "Unsupported word size"
#endif /* B_PER_W */

/*!
*******************************************************************************
\file word.h

Макросы сравнений введены для того, чтобы поддержать (и подчеркнуть) 
регулярный, т. е. без ветвлений, характер сравнений. На известных аппаратных 
платформах обычные сравнения a < b, a > b, a == b,... регулярны. Поэтому 
реализованные макросы являются псевдонимами этих сравнений. 

Если обычные сравнения все таки не регулярны, то можно использовать следующие 
универсальные (но медленные) макросы [1, с. 35]:
\code
#define wordLess(a, b)\
	((~(a) & (b) | ((~(a) | (b)) & (a) - (b))) >> (B_PER_W - 1))
#define wordLeq(a, b)\
	(((~(a) | (b)) & (((a) ^ (b)) | ~((b) - (a)))) >> (B_PER_W - 1))
...
\endcode

Макросы сравнений без суффиксов 01 и 0M возвращают результат типа int. 

Макросы с суффиксом 01 возвращают результат типа word, который принимает
значения 0 (WORD_0) или 1 (WORD_1). Эти макросы удобно использовать 
в арифметике больших чсел.

Макросы с суффиксом 0M меняют WORD_1 на WORD_MAX. Возвращаемые значения 
можно использовать как маски при организации регулярных вычислений.

\def wordEq 
\brief Машинные слова a и b равны?
\def wordEq01
\brief Машинные слова a и b равны (WORD_0 / WORD_1)? 
\def wordEq0M
\brief Машинные слова a и b равны  (WORD_0 / WORD_MAX)?

\def wordNeq 
\brief Машинные слова a и b не равны?
\def wordNeq01
\brief Машинные слова a и b не равны (WORD_0 / WORD_1)?
\def wordNeq0M
\brief Машинные слова a и b не равны (WORD_0 / WORD_MAX)?

\def wordLess
\brief Машинное слово a меньше машинного слова b?
\def wordLess01
\brief Машинное слово a меньше машинного слова b (WORD_0 / WORD_1)?
\def wordLess0M
\brief Машинное слово a меньше машинного слова b (WORD_0 / WORD_MAX)?

\def wordLeq
\brief Машинное слово a не больше машинного слова b?
\def wordLeq01
\brief Машинное слово a не больше машинного слова b  (WORD_0 / WORD_1)?
\def wordLeq0M
\brief Машинное слово a не больше машинного слова b  (WORD_0 / WORD_MAX)?

\def wordGreater
\brief Машинное слово a больше машинного слова b?
\def wordGreater01
\brief Машинное слово a больше машинного слова b (WORD_0 / WORD_1)?
\def wordGreater0M
\brief Машинное слово a больше машинного слова b (WORD_0 / WORD_MAX)?

\def wordGeq
\brief Машинное слово a не меньше машинного слова b?
\def wordGeq01
\brief Машинное слово a не меньше машинного слова b  (WORD_0 / WORD_1)?
\def wordGeq0M
\brief Машинное слово a не меньше машинного слова b  (WORD_0 / WORD_MAX)?
*******************************************************************************
*/

#define wordEq(a, b) ((word)(a) == (word)(b))
#define wordNeq(a, b) ((word)(a) != (word)(b))
#define wordLess(a, b) ((word)(a) < (word)(b))
#define wordLeq(a, b) ((word)(a) <= (word)(b))
#define wordGreater(a, b) wordLess(b, a)
#define wordGeq(a, b) wordLeq(b, a)

#define wordEq01(a, b) ((word)wordEq(a, b))
#define wordNeq01(a, b) ((word)wordNeq(a, b))
#define wordLess01(a, b) ((word)wordLess(a, b))
#define wordLeq01(a, b) ((word)wordLeq(a, b))
#define wordGreater01(a, b) ((word)wordGreater(a, b))
#define wordGeq01(a, b) ((word)wordGeq(a, b))

#define wordEq0M(a, b) ((word)(wordNeq01(a, b) - WORD_1))
#define wordNeq0M(a, b) ((word)(wordEq01(a, b) - WORD_1))
#define wordLess0M(a, b) ((word)(wordGeq01(a, b) - WORD_1))
#define wordLeq0M(a, b) ((word)(wordGreater01(a, b) - WORD_1))
#define wordGreater0M(a, b) ((word)(wordLeq01(a, b) - WORD_1))
#define wordGeq0M(a, b) ((word)(wordLess01(a, b) - WORD_1))

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_WORD_H */
