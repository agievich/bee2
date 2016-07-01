/*
*******************************************************************************
\file zz_int.h
\brief Multiple-precision unsigned integers: internal definitions
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2016.07.01
\version 2016.07.01
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/defs.h"

/*
*******************************************************************************
Примитивы регуляризации
*******************************************************************************
*/

word zzSubAndW(word b[], const word a[], size_t n, register word w);
void zzAddAndW(word b[], const word a[], size_t n, register word w);

/*
*******************************************************************************
Макросы умножения слов

_MUL:
	dword c;
	word a, b;
	c <- a, c <- c * b;

_MUL_LO:
	word a, b;
	return (word)(a * b);

\todo _MUL_HI.
*******************************************************************************
*/

#if defined(_MSC_VER) && (B_PER_W == 32)
	#include <intrin.h>
	#define _MUL(c, a, b)\
		(c) = __emulu((word)(a), (word)(b))
#else
	#define _MUL(c, a, b)\
		(c) = (word)(a), (c) *= (word)(b)
#endif 

#define _MUL_LO(c, a, b)\
	(c) = (word)(a) * (word)(b);
