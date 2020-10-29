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

#if 0
#if defined(__AVX512F__)
#define BASH_AVX512
#elif defined(__AVX2__)
#define BASH_AVX2
#elif defined(__SSE2__)
#define BASH_SSE2
#elif defined(__ARM_NEON__) || defined(__ARM_NEON) || defined (__ARM_FP16_FORMAT_IEEE) || defined (__ARM_FP16_FORMAT_ALTERNATIVE)
#define BASH_NEON
#elif !defined(U64_SUPPORT)
#define BASH_32
#else
#define BASH_64
#endif
#endif

#if defined(BASH_AVX512)
	#include "bash_favx512.c"
	const char bash_platform[] = "BASH_AVX512";
#elif defined(BASH_AVX2)
	#include "bash_favx2.c"
	const char bash_platform[] = "BASH_AVX2";
#elif defined(__SSE2__) && defined(BASH_SSE2)
	#include "bash_fsse2.c"
	const char bash_platform[] = "BASH_SSE2";
#elif defined(BASH_NEON)
	#include "bash_fneon.c"
	const char bash_platform[] = "BASH_NEON";
#elif defined(BASH_32)
	#include "bash_f32.c"
	const char bash_platform[] = "BASH_32";
#else
	#include "bash_f64.c"
	const char bash_platform[] = "BASH_64";
#endif
