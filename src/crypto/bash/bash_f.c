/*
*******************************************************************************
\file bash_f.c
\brief STB 34.101.77 (bash): bash-f
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2019.06.25
\version 2019.07.10
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/defs.h"

#if defined(__AVX512F__) && defined(BASH_AVX512)
	#include "bash_favx512.c"
	const char bash_platform[] = "BASH_AVX512";
#elif defined(__AVX2__) && defined(BASH_AVX2)
	#include "bash_favx2.c"
	const char bash_platform[] = "BASH_AVX2";
#elif defined(__SSE2__) && defined(BASH_SSE2)
	#include "bash_fsse2.c"
	const char bash_platform[] = "BASH_SSE2";
#elif !defined(U64_SUPPORT) || defined(BASH_32)
	#include "bash_f32.c"
	const char bash_platform[] = "BASH_32";
#else
	#include "bash_f64.c"
	const char bash_platform[] = "BASH_64";
#endif
