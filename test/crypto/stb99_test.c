/*
*******************************************************************************
\file stb99_test.c
\brief Tests for STB 1176.2-99[generation of parameters]
\project bee2/test
\created 2023.08.05
\version 2023.08.05
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/math/ww.h>
#include <bee2/math/zz.h>
#include <bee2/crypto/stb99.h>

/*
*******************************************************************************
Самотестирование

Реализованы тесты из Методики НИИ ППМИ.

\remark Тесты PFOK.GENP.2-4, реализованные в функции pfokTestStdParams(),
выполняются очень долго и поэтому заблокированы.
*******************************************************************************
*/

bool_t stb99TestTestParams()
{
	stb99_params params[1];
	stb99_params params1[1];
	stb99_seed seed[1];
	// тест STB.GENP.1
	if (stb99StdParams(params, seed, "test") != ERR_OK ||
		stb99GenParams(params1, seed) != ERR_OK ||
		stb99ValParams(params1) != ERR_OK ||
		params->l != params1->l || params->r != params1->r ||
		!memEq(params->p, params1->p, O_OF_B(params->l)) ||
		!memEq(params->q, params1->q, O_OF_B(params->r)) ||
		!memEq(params->a, params1->a, O_OF_B(params->l)))
		return FALSE;
	// все нормально
	return TRUE;
}

bool_t stb99TestStdParams()
{
	stb99_params params[1];
	stb99_params params1[1];
	stb99_seed seed[1];
	// тест STB.GENP.2
	if (stb99StdParams(params, seed, "1.2.112.0.2.0.1176.2.3.3.1") != ERR_OK ||
		stb99ValParams(params) != ERR_OK ||
		stb99GenParams(params1, seed) != ERR_OK ||
		params->l != params1->l || params->r != params1->r ||
		!memEq(params->p, params1->p, O_OF_B(params->l)) ||
		!memEq(params->q, params1->q, O_OF_B(params->r)) ||
		!memEq(params->a, params1->a, O_OF_B(params->l)))
		return FALSE;
	// тест STB.GENP.3
	if (stb99StdParams(params, seed, "1.2.112.0.2.0.1176.2.3.6.1") != ERR_OK ||
		stb99GenParams(params1, seed) != ERR_OK ||
		params->l != params1->l || params->r != params1->r ||
		!memEq(params->p, params1->p, O_OF_B(params->l)) ||
		!memEq(params->q, params1->q, O_OF_B(params->r)) ||
		!memEq(params->a, params1->a, O_OF_B(params->l)))
		return FALSE;
	// тест STB.GENP.4
	if (stb99StdParams(params, seed, "1.2.112.0.2.0.1176.2.3.10.1") != ERR_OK ||
		stb99GenParams(params1, seed) != ERR_OK ||
		params->l != params1->l || params->r != params1->r ||
		!memEq(params->p, params1->p, O_OF_B(params->l)) ||
		!memEq(params->q, params1->q, O_OF_B(params->r)) ||
		!memEq(params->a, params1->a, O_OF_B(params->l)))
		return FALSE;
	// все нормально
	return TRUE;
}

bool_t stb99Test()
{
	return stb99TestTestParams() && stb99TestStdParams();
}
