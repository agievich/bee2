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

int testMath()
{
	bool_t code;
	int ret = 0;
	printf("priTest: %s\n", (code = priTest()) ? "OK" : "Err"), ret |= !code;
	printf("zzTest: %s\n", (code = zzTest()) ? "OK" : "Err"), ret |= !code;
	printf("wordTest: %s\n", (code = wordTest()) ? "OK" : "Err"), ret |= !code;
	printf("wwTest: %s\n", (code = wwTest()) ? "OK" : "Err"), ret |= !code;
	printf("ecpTest: %s\n", (code = ecpTest()) ? "OK" : "Err"), ret |= !code;
	code = ecpBench(), ret |= !code;
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

int testCrypto()
{
	bool_t code;
	int ret = 0;
	printf("beltTest: %s\n", (code = beltTest()) ? "OK" : "Err"), ret |= !code;
	printf("bashTest: %s\n", (code = bashTest()) ? "OK" : "Err"), ret |= !code;
	code = beltBench(), ret |= !code;
	code = bashBench(), ret |= !code;
	printf("bignTest: %s\n", (code = bignTest()) ? "OK" : "Err"), ret |= !code;
	printf("botpTest: %s\n", (code = botpTest()) ? "OK" : "Err"), ret |= !code;
	printf("brngTest: %s\n", (code = brngTest()) ? "OK" : "Err"), ret |= !code;
	printf("belsTest: %s\n", (code = belsTest()) ? "OK" : "Err"), ret |= !code;
	printf("bakeTest: %s\n", (code = bakeTest()) ? "OK" : "Err"), ret |= !code;
	printf("dstuTest: %s\n", (code = dstuTest()) ? "OK" : "Err"), ret |= !code;
	printf("g12sTest: %s\n", (code = g12sTest()) ? "OK" : "Err"), ret |= !code;
	printf("pfokTest: %s\n", (code = pfokTest()) ? "OK" : "Err"), ret |= !code;
	printf("bpkiTest: %s\n", (code = bpkiTest()) ? "OK" : "Err"), ret |= !code;
	return ret;
}

/*
*******************************************************************************
main
*******************************************************************************
*/

int main()
{
	int ret = 0;
	ret |= testCore();
	ret |= testMath();
	ret |= testCrypto();
	return ret;
}
