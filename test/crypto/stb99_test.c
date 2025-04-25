/*
*******************************************************************************
\file stb99_test.c
\brief Tests for STB 1176.2-99[generation of parameters]
\project bee2/test
\created 2023.08.05
\version 2025.04.25
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/crypto/stb99.h>

/*
*******************************************************************************
Самотестирование

Реализованы тесты из Методики НИИ ППМИ.

Тест GPQA.LNN -- это объединение тестов GPQ.LNN и GA.LNN Методики.
В тесте GPQ.LNN проверяется генерация параметров p, q уровня NN,
в тесте GA.LNN -- генерация параметра a.

В функции stb99TestParamsTest() реализован тест GPQA.L01.

В функции stb99TestParamsStd() реализованы тесты GPQA.L03, GPQA.L06, GPQA.L10.
В этих тестах проверяется корректность генерации стандартных параметров,
определенных в СТБ 34.101.50.

\remark Тесты GPQA.L{03,06,10}, реализованные в функции stb99TestParamsStd(),
выполняются достаточно долго и поэтому заблокированы.
*******************************************************************************
*/

bool_t stb99TestParamsTest()
{
	stb99_seed seed[1];
	stb99_seed seed1[1];
	stb99_params params[1];
	stb99_params params1[1];
	// проверка затравочных параметров
	memSetZero(seed1, sizeof(stb99_seed));
	if (stb99SeedVal(seed1) == ERR_OK ||
		stb99ParamsStd(params, seed, "test") != ERR_OK ||
		(seed1->l = params->l, stb99SeedAdj(seed1)) != ERR_OK ||
		!memEq(seed, seed1, sizeof(stb99_seed)))
		return FALSE;
	// доопределение затравочных параметров
	memCopy(seed1->zi, seed->zi, sizeof(seed->zi));
	if (stb99SeedAdj(seed1) != ERR_OK ||
		!memEq(seed, seed1, sizeof(stb99_seed)) ||
		(seed1->di[4] = 0, stb99SeedVal(seed1)) == ERR_OK ||
		(seed1->di[4] = SIZE_MAX / 5 - 1, stb99SeedVal(seed1)) == ERR_OK)
		return FALSE;
	memSetZero(seed1->di, sizeof(seed1->di));
	if (stb99SeedAdj(seed1) != ERR_OK ||
		stb99SeedVal(seed1) != ERR_OK ||
		!memEq(seed, seed1, sizeof(stb99_seed)) ||
		(seed1->ri[3] = 0, stb99SeedVal(seed1)) == ERR_OK ||
		(seed1->ri[3] = SIZE_MAX / 5 - 1, stb99SeedVal(seed1)) == ERR_OK)
		return FALSE;
	memSetZero(seed1->ri, sizeof(seed1->ri));
	if (stb99SeedAdj(seed1) != ERR_OK ||
		stb99SeedVal(seed1) != ERR_OK ||
		!memEq(seed, seed1, sizeof(stb99_seed)))
		return FALSE;
	// тест GPQA.L01
	if (stb99ParamsStd(params, 0, "test") != ERR_OK ||
		stb99ParamsGen(params1, seed1) != ERR_OK ||
		stb99ParamsVal(params1) != ERR_OK ||
		!memEq(params, params1, sizeof(stb99_params)))
		return FALSE;
	// испортить параметры
	params1->d[0] += 2;
	if (stb99ParamsVal(params1) == ERR_OK)
		return FALSE;
	// все нормально
	return TRUE;
}

bool_t stb99TestParamsStd()
{
	stb99_params params[1];
	stb99_params params1[1];
	stb99_seed seed[1];
	// тест GPQA.L03
	if (stb99ParamsStd(params, seed, "1.2.112.0.2.0.1176.2.3.3.1") != ERR_OK ||
		stb99ParamsGen(params1, seed) != ERR_OK ||
		!memEq(params, params1, sizeof(stb99_params)))
		return FALSE;
	// тест GPQA.L06
	if (stb99ParamsStd(params, seed, "1.2.112.0.2.0.1176.2.3.6.1") != ERR_OK ||
		stb99ParamsGen(params1, seed) != ERR_OK ||
		!memEq(params, params1, sizeof(stb99_params)))
		return FALSE;
	// тест GPQA.L10
	if (stb99ParamsStd(params, seed, "1.2.112.0.2.0.1176.2.3.10.1") != ERR_OK ||
		stb99ParamsGen(params1, seed) != ERR_OK ||
		!memEq(params, params1, sizeof(stb99_params)))
		return FALSE;
	// все нормально
	return TRUE;
}

bool_t stb99TestParamsStd2()
{
	stb99_params params[1];
	stb99_seed seed[1];
	// проверка параметров теста GPQA.L03
	if (stb99ParamsStd(params, seed, "1.2.112.0.2.0.1176.2.3.3.1") != ERR_OK ||
		stb99SeedVal(seed) != ERR_OK ||
		stb99ParamsVal(params) != ERR_OK)
		return FALSE;
	// проверка параметров теста GPQA.L06
	if (stb99ParamsStd(params, seed, "1.2.112.0.2.0.1176.2.3.6.1") != ERR_OK ||
		stb99SeedVal(seed) != ERR_OK ||
		stb99ParamsVal(params) != ERR_OK)
		return FALSE;
	// проверка параметров теста GPQA.L10
	if (stb99ParamsStd(params, seed, "1.2.112.0.2.0.1176.2.3.10.1") != ERR_OK ||
		stb99SeedVal(seed) != ERR_OK ||
		stb99ParamsVal(params) != ERR_OK)
		return FALSE;
	// все нормально
	return TRUE;
}

bool_t stb99Test()
{
	return stb99TestParamsTest() && stb99TestParamsStd2();
}
