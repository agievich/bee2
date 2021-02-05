/*
*******************************************************************************
\file test.c
\brief Bee2 testing
\project bee2/test
\author Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.04.02
\version 2021.05.15
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <stdio.h>
#include <bee2/defs.h>

/*
*******************************************************************************
Тестирование модулей core
*******************************************************************************
*/

extern bool_t b64Test();
extern bool_t decTest();
extern bool_t derTest();
extern bool_t hexTest();
extern bool_t memTest();
extern bool_t mtTest();
extern bool_t objTest();
extern bool_t oidTest();
extern bool_t prngTest();
extern bool_t rngTest();
extern bool_t strTest();
extern bool_t tmTest();
extern bool_t u16Test();
extern bool_t u32Test();
extern bool_t u64Test();
extern bool_t utilTest();

int testCore()
{
	bool_t code;
	int ret = 0;
	printf("b64Test: %s\n", (code = b64Test()) ? "OK" : "Err"), ret |= !code;
	printf("decTest: %s\n", (code = decTest()) ? "OK" : "Err"), ret |= !code;
	printf("derTest: %s\n", (code = derTest()) ? "OK" : "Err"), ret |= !code;
	printf("hexTest: %s\n", (code = hexTest()) ? "OK" : "Err"), ret |= !code;
	printf("memTest: %s\n", (code = memTest()) ? "OK" : "Err"), ret |= !code;
	printf("mtTest: %s\n", (code = mtTest()) ? "OK" : "Err"), ret |= !code;
	printf("objTest: %s\n", (code = objTest()) ? "OK" : "Err"), ret |= !code;
	printf("oidTest: %s\n", (code = oidTest()) ? "OK" : "Err"), ret |= !code;
	printf("genTest: %s\n", (code = prngTest()) ? "OK" : "Err"), ret |= !code;
	printf("rngTest: %s\n", (code = rngTest()) ? "OK" : "Err"), ret |= !code;
	printf("strTest: %s\n", (code = strTest()) ? "OK" : "Err"), ret |= !code;
	printf("tmTest: %s\n", (code = tmTest()) ? "OK" : "Err"), ret |= !code;
	printf("u16Test: %s\n", (code = u16Test()) ? "OK" : "Err"), ret |= !code;
	printf("u32Test: %s\n", (code = u32Test()) ? "OK" : "Err"), ret |= !code;
	printf("u64Test: %s\n", (code = u64Test()) ? "OK" : "Err"), ret |= !code;
	printf("utilTest: %s\n", (code = utilTest()) ? "OK" : "Err"), ret |= !code;
	return ret;
}

/*
*******************************************************************************
Тестирование модулей math
*******************************************************************************
*/

extern bool_t wwTest();
extern bool_t priTest();
extern bool_t zzTest();
extern bool_t wordTest();
extern bool_t ecpTest();
extern bool_t ecpBench();

bool_t fTest;
bool_t fBench;

int testMath()
{
	bool_t code;
	int ret = 0;
	//printf("priTest: %s\n", (code = priTest()) ? "OK" : "Err"), ret |= !code;
	//printf("zzTest: %s\n", (code = zzTest()) ? "OK" : "Err"), ret |= !code;
	//printf("wordTest: %s\n", (code = wordTest()) ? "OK" : "Err"), ret |= !code;
	//printf("wwTest: %s\n", (code = wwTest()) ? "OK" : "Err"), ret |= !code;
	if(fTest) printf("ecpTest: %s\n", (code = ecpTest()) ? "OK" : "Err"), ret |= !code;
	if(fBench) code = ecpBench(), ret |= !code;
	return ret;
}

/*
*******************************************************************************
Тестирование модулей crypto
*******************************************************************************
*/

extern bool_t beltTest();
extern bool_t beltBench();
extern bool_t bignTest();
extern bool_t brngTest();
extern bool_t belsTest();
extern bool_t bakeTest();
extern bool_t dstuTest();
extern bool_t g12sTest();
extern bool_t pfokTest();
extern bool_t pfokTestStdParams();
extern bool_t bakeDemo();
extern bool_t bashTest();
extern bool_t bashBench();
extern bool_t botpTest();
extern bool_t bpkiTest();
extern bool_t bignBench();
extern bool_t bakeBench();


int testCrypto()
{
	bool_t code;
	int ret = 0;
//	printf("beltTest: %s\n", (code = beltTest()) ? "OK" : "Err"), ret |= !code;
//	printf("bashTest: %s\n", (code = bashTest()) ? "OK" : "Err"), ret |= !code;
//	code = beltBench(), ret |= !code;
//	code = bashBench(), ret |= !code;
	if(fTest) printf("bignTest: %s\n", (code = bignTest()) ? "OK" : "Err"), ret |= !code;
	if(fBench) code = bignBench(),	ret |= !code;
//	printf("botpTest: %s\n", (code = botpTest()) ? "OK" : "Err"), ret |= !code;
//	printf("brngTest: %s\n", (code = brngTest()) ? "OK" : "Err"), ret |= !code;
//	printf("belsTest: %s\n", (code = belsTest()) ? "OK" : "Err"), ret |= !code;
	if(fTest) printf("bakeTest: %s\n", (code = bakeTest()) ? "OK" : "Err"), ret |= !code;
	if(fBench) code = bakeBench(),	ret |= !code;
//	printf("dstuTest: %s\n", (code = dstuTest()) ? "OK" : "Err"), ret |= !code;
//	printf("g12sTest: %s\n", (code = g12sTest()) ? "OK" : "Err"), ret |= !code;
//	printf("pfokTest: %s\n", (code = pfokTest()) ? "OK" : "Err"), ret |= !code;
//	printf("bpkiTest: %s\n", (code = bpkiTest()) ? "OK" : "Err"), ret |= !code;
	return ret;
}

/*
*******************************************************************************
main
*******************************************************************************
*/


size_t testReps = 2;
extern bool_t ecSafe;
extern bool_t ecPrecomp;
extern bool_t ecPrecompA;
extern bool_t bignPrecomp;
extern bool_t ecpDivp;
extern size_t ecW;

#define countof(a) (sizeof(a)/sizeof(*(a)))

int run()
{
	int ret = 0;
	printf(
		"\n===================================="
		"\n%s %s %s w=%d"
		"\n===================================="
		"\n"
		, ecSafe ? "SAFE" : "FAST"
		, ecPrecomp ? (bignPrecomp ? (ecPrecompA ? "PrecompA" : "PrecompJ") : "NoPrecomp") : "Orig"
		, ecPrecomp ? (ecpDivp ? "Divp" : "Add2") : ""
		, (int)ecW);
	ret |= testMath();
	ret |= testCrypto();
	return ret;
}

int all()
{
	int ret = 0;
	size_t i, j, k, l, m;
	bool_t safe[] = { TRUE, FALSE, };
	bool_t precomp[] = { TRUE, FALSE, };
	bool_t with_precomp[] = { TRUE, FALSE, };
	bool_t divp[] = { /*FALSE,*/ TRUE, };
	bool_t precompA[] = { TRUE, /*FALSE,*/ };

	fTest = TRUE;
	fBench = TRUE;

	for(i = 0; i < countof(safe); ++i)
	{
		ecSafe = safe[i];
		for(j = 0; j < countof(precomp); ++j)
		{
			ecPrecomp = precomp[j];
			for(m = 0; m < countof(precompA); ++m)
			{
				ecPrecompA = precompA[m];
				for(k = 0; k < countof(with_precomp); ++k)
				{
					bignPrecomp = with_precomp[k];
					for(l = 0; l < countof(divp); ++l)
					{
						ecpDivp = divp[l];
						for(ecW = 2; ecW++ < 6;)
						{
							ret |= run();
						}
						if(!ecPrecomp) break;
					}
					if(!ecPrecomp) break;
				}
				if(!ecPrecomp) break;
			}
		}
	}
	return ret;
}

#include <string.h>
#include <stdlib.h>
int main(int argc, char const **argv)
{
	static char const *help =
		"Args: safe precomp precompa bignprecomp divp w <W> test bench reps <R> all help\n"
		"\n"
		"\tsafe       : enable safe (regular) windowed method, or fast (irregular) naf otherwise\n"
		"\tprecomp    : enable precomputations (new algorithm), or base-line original algorithm otherwise\n"
		"\tprecompa   : enable precomputations in affine coordinates, or in jacobian otherwise (doesn't work ATM)\n"
		"\tbignprecomp: enable precomputation tables for bign/bake algorithms, or no tables otherwise\n"
		"\tdivp       : enable small mult computations via division polynomials, or using 'add 2p' method otherwise\n"
		"\tw <W>      : set window size for windowed/naf methods, usually 3<=W<=6\n"
		"\ttest       : enable tests\n"
		"\tbench      : enable benchmarks\n"
		"\treps <R>   : set number of reps for benchmarks, usually 2<=R<=1000\n"
		"\tall        : enable all configurations and run tests and benchmarks\n"
		"\thelp       : show this help\n"
		"\n"
		"Example: safe precomp precompa bignprecomp divp w 3 test bench reps \n"
		"    Enable safe (regular) windowed method with full precomputation in affine coordinates\n"
		"    using division polynomials with window size 3 and run tests and benchmarks\n"
		"\n"
		"Example: precomp precompa bignprecomp divp w 4 bench\n"
		"    Enable fast (irregular) naf method with full precomputation in affine coordinates\n"
		"    using division polynomials with window size 4 and run benchmarks only\n"
		"\n"
		"Example: safe w 4 bench\n"
		"    Enable the original (baseline) safe (regular) windowed method without precomputations\n"
		"    with window size 4 and run benchmarks only\n"
		"\n"
		"Example: w 5 reps 10 bench\n"
		"    Enable the original (baseline) fast (irregular) naf method without precomputations\n"
		"    with window size 5 and run benchmarks only\n"
		"\n"
		"Example: w 4 reps 10 all\n"
		"    Run all possible configurations of tests and benchmarks\n"
		"\n"
		;
	fTest = FALSE;
	fBench = FALSE;
	ecSafe = FALSE;
	ecPrecomp = FALSE;
	ecPrecompA = FALSE;
	bignPrecomp = FALSE;
	ecpDivp = FALSE;
	ecW = 3;

	if(argc < 2)
	{
		printf("Try 'help' for help. Running all configurations now\n");
		return all();
	}

	for(; --argc;)
	{
		++argv;
		if(!strcmp("safe", *argv))
			ecSafe = TRUE;
		else if(!strcmp("precomp", *argv))
			ecPrecomp = TRUE;
		else if(!strcmp("precompa", *argv))
			ecPrecompA = TRUE;
		else if(!strcmp("bignprecomp", *argv))
			bignPrecomp = TRUE;
		else if(!strcmp("divp", *argv))
			ecpDivp = TRUE;
		else if(!strcmp("w", *argv))
		{
			if(--argc)
				ecW = (size_t)atoi(*++argv);
		}
		else if(!strcmp("reps", *argv))
		{
			if(--argc)
				testReps = (size_t)atoi(*++argv);
		}
		else if(!strcmp("test", *argv))
			fTest = TRUE;
		else if(!strcmp("bench", *argv))
			fBench = TRUE;
		else if(!strcmp("all", *argv))
			return all();
		else if(!strcmp("help", *argv))
		{
			printf("ecsafe\n\n%s", help);
			return 0;
		}
		else
		{
			printf("Unknown option [%s].", *argv);
			return 1;
		}
	}

	if(!fTest && !fBench)
	{
		fTest = TRUE;
		fBench = TRUE;
	}
	return run();
}
