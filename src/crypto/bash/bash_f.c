/*
*******************************************************************************
\file bash_f.c
\brief STB 34.101.77 (bash): bash-f
\project bee2 [cryptographic library]
\created 2019.06.25
\version 2021.03.25
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/defs.h"

#if !defined(__ARM_NEON__) && (defined(__ARM_NEON) ||\
	defined(__ARM_FP16_FORMAT_IEEE) || defined(__ARM_FP16_FORMAT_ALTERNATIVE) ||\
	defined(_M_ARM) || defined(_M_ARM64))
	#define __ARM_NEON__
#endif

#if !defined(__SSE2__) && ((_M_IX86_FP == 2) ||\
	defined(_M_AMD64) || defined(_M_X64))
	#define __SSE2__
#endif

#if defined(__AVX512F__) && defined(BASH_AVX512)
	#include "bash_favx512.c"
	const char bash_platform[] = "BASH_AVX512";
#elif defined(__AVX2__) && defined(BASH_AVX2)
	#include "bash_favx2.c"
	const char bash_platform[] = "BASH_AVX2";
#elif defined(__SSE2__) && defined(BASH_SSE2)
	#include "bash_fsse2.c"
	const char bash_platform[] = "BASH_SSE2";
#elif defined(__ARM_NEON__) && defined(BASH_NEON)
	#include "bash_fneon.c"
	const char bash_platform[] = "BASH_NEON";
#elif !defined(U64_SUPPORT) || defined(BASH_32)
	#include "bash_f32.c"
	const char bash_platform[] = "BASH_32";
#else
	#include "bash_f64.c"
	const char bash_platform[] = "BASH_64";
#endif
