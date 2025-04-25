/*
*******************************************************************************
\file brng_test.c
\brief Tests for STB 34.101.47 (brng)
\project bee2/test
\created 2013.04.01
\version 2025.04.25
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/crypto/brng.h>
#include <bee2/crypto/belt.h>

/*
*******************************************************************************
Самотестирование

-#	Выполняются тесты из приложения Б к СТБ 34.101.47.
-#	Номера тестов соответствуют номерам таблиц приложения.
-#	Тесты Б.1 реализованы в belt-test.
-#	Тесты Б.3 (brng-ctr-stb11761) не реализованы.
-#	В тесте Б.2 используется больше проверок, чем указано в таблице.
	Дополнительные данные нужны для построения тестов в других стандартах.
-#	Дополнительные тесты покрывают ошибки, выявленные в результате испытаний.
*******************************************************************************
*/

bool_t brngTest()
{
	octet buf[256];
	octet buf1[256];
	octet iv[128];
	octet iv1[32];
	octet state[1024];
	// подготовить память
	if (sizeof(state) < brngCTR_keep() ||
		sizeof(state) < brngHMAC_keep())
		return FALSE;
	// тест Б.2
	memCopy(buf, beltH(), 256);
	brngCTRStart(state, beltH() + 128, beltH() + 128 + 64);
	brngCTRStepR(buf, 32, state);
	brngCTRStepR(buf + 32, 32, state);
	brngCTRStepR(buf + 64, 32, state);
	brngCTRStepG(iv, state);
	brngCTRStepR(buf + 96, 256 - 96, state);
	if (!hexEq(buf, 
		"1F66B5B84B7339674533F0329C74F218"
		"34281FED0732429E0C79235FC273E269"
		"4C0E74B2CD5811AD21F23DE7E0FA742C"
		"3ED6EC483C461CE15C33A77AA308B7D2"
		"0F51D91347617C20BD4AB07AEF4F26A1"
		"AD1362A8F9A3D42FBE1B8E6F1C88AAD5"
		"0A4E8298BE0839E46F19409F637F4415"
		"572251DD0D39284F0F0390D93BBCE9EC"
		"F81B29D571F6452FF8B2B97F57E18A58"
		"BC946FEE45EAB32B06FCAC23A33F422B"
		"C431B41BBE8E802288737ACF45A29251"
		"FC736A3C6F478F77A7ED271D5EEDAA58"
		"E98309303623AFD33017C42BC6D43C15"
		"438446EE57D46E412EFC0B61B5FBA39E"
		"D37BABE50BFEEB8ED162BB1393D46FB4"
		"3534A201EB3B1A5C085DC5068ED6F89A"))
		return FALSE;
	if (!hexEq(iv, 
		"C132971343FC9A48A02A885F194B09A1"
		"7ECDA4D01544AF8CA58450BF66D2E88A"))
		return FALSE;
	memCopy(buf1, beltH(), 96);
	memCopy(iv1, beltH() + 128 + 64, 32);
	brngCTRRand(buf1, 96, beltH() + 128, iv1);
	if (!memEq(buf, buf1, 96) || !memEq(iv, iv1, 32))
		return FALSE;
	// тест Б.4
	brngHMACStart(state, beltH() + 128, 32, beltH() + 128 + 64, 32);
	brngHMACStepR(buf, 32, state);
	brngHMACStepR(buf + 32, 11, state);
	brngHMACStepR(buf + 32 + 11, 19, state);
	brngHMACStepR(buf + 32 + 30, 2, state);
	brngHMACStepR(buf + 64, 32, state);
	if (!hexEq(buf, 
		"AF907A0E470A3A1B268ECCCCC0B90F23"
		"9FE94A2DC6E014179FC789CB3C3887E4"
		"695C6B96B84948F8D76924E22260859D"
		"B9B5FE757BEDA2E17103EE44655A9FEF"
		"648077CCC5002E0561C6EF512C513B8C"
		"24B4F3A157221CFBC1597E969778C1E4"))
		return FALSE;
	memCopy(buf1, beltH(), 96);
	brngHMACRand(buf1, 96, beltH() + 128, 32, beltH() + 128 + 64, 32);
	if (!memEq(buf, buf1, 96)) 
		return FALSE;
	// дополнительный тест: короткие ключ, синхропосылка и выходной блок
	brngHMACStart(state, beltH() + 128, 1, beltH() + 128 + 64, 1);
	brngHMACStepR(buf, 2, state);
	brngHMACRand(buf1, 2, beltH() + 128, 1, beltH() + 128 + 64, 1);
	if (!memEq(buf, buf1, 2))
		return FALSE;
	if (!hexEq(buf, 
		"42B1"))
		return FALSE;
	// дополнительный тест: длинный ключ, длинная синхропосылка
	memCopy(iv, beltH(), 127);
	brngHMACStart(state, beltH() + 128, 127, iv, 127);
	brngHMACStepR(buf, 256, state);
	brngHMACRand(buf1, 256, beltH() + 128, 127, iv, 127);
	if (!memEq(buf, buf1, 256))
		return FALSE;
	// дополнительный тест: длинная волатильная синхропосылки
	brngHMACStart(state, beltH() + 128, 127, iv, 127);
	iv[0]++;
	brngHMACStepR(buf, 256, state);
	if (memEq(buf, buf1, 256))
		return FALSE;
	// все нормально
	return TRUE;
}
