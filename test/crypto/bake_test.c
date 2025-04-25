/*
*******************************************************************************
\file bake_test.c
\brief Tests for STB 34.101.66 (bake)
\project bee2/test
\created 2014.04.23
\version 2025.04.25
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include <stdarg.h>
#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bake.h>

/*
*******************************************************************************
Проверочный канал связи как набор буферов памяти

Сообщение протокола описывается структурой типа msg_t. Сообщения хранятся
в массиве _msgs и обрабатываются с помощью функций fileMsgWrite(),
fileMmsgRead().
*******************************************************************************
*/

typedef struct
{
	bool_t valid;		/* сообщение задано? */
	octet buf[1024];	/* содержимое сообщения */
	size_t len;			/* длина содержимого */
} msg_t;

static msg_t _msgs[4];

typedef struct
{
	size_t i;			/* номер сообщения */
	size_t offset;		/* смещение в содержимом сообщения (при чтении) */
} file_msg_st;

static err_t fileMsgWrite(size_t* written, const void* buf, size_t count,
	void* file)
{
	file_msg_st* f;
	// pre
	ASSERT(memIsValid(file, sizeof(file_msg_st)));
	ASSERT(memIsValid(buf, count));
	ASSERT(memIsValid(written, sizeof(size_t)));
	// найти сообщение
	f = (file_msg_st*)file;
	if (f->i >= 4)
		return ERR_FILE_WRITE;
	// записать
	if (count > sizeof(_msgs[f->i].buf))
		return ERR_OUTOFMEMORY;
	_msgs[f->i].valid = TRUE;
	memCopy(_msgs[f->i].buf, buf, count);
	*written = _msgs[f->i].len = count;
	// к следующему сообщению
	++f->i, f->offset = 0;
	// все нормально
	return ERR_OK;
}

static err_t fileMsgRead(size_t* read, void* buf, size_t count, void* file)
{
	file_msg_st* f;
	// pre
	ASSERT(memIsValid(file, sizeof(file_msg_st)));
	ASSERT(memIsValid(buf, count));
	ASSERT(memIsValid(read, sizeof(size_t)));
	// найти сообщение
	f = (file_msg_st*)file;
	if (f->i >= 4)
		return ERR_FILE_READ;
	if (!_msgs[f->i].valid)
		return ERR_FILE_NOT_FOUND;
	// прочитать частично?
	ASSERT(f->offset <= _msgs[f->i].len);
	if (count + f->offset > _msgs[f->i].len)
	{
		memCopy(buf, _msgs[f->i].buf + f->offset,
			*read = _msgs[f->i].len - f->offset);
		++f->i, f->offset = 0;
		return ERR_MAX;
	}
	// прочитать полностью
	memCopy(buf, _msgs[f->i].buf + f->offset, *read = count);
	f->offset += count;
	// конец сообщения?
	if (f->offset == _msgs[f->i].len)
		++f->i, f->offset = 0;
	// все нормально
	return ERR_OK;
}

static void fileMsgFlash()
{
	memSetZero(_msgs, sizeof(_msgs));
}

/*
*******************************************************************************
Самотестирование: таблица Б.1
*******************************************************************************
*/

static const char _da[] =
	"1F66B5B84B7339674533F0329C74F218"
	"34281FED0732429E0C79235FC273E269";

static const char _db[] =
	"4C0E74B2CD5811AD21F23DE7E0FA742C"
	"3ED6EC483C461CE15C33A77AA308B7D2";

static const char _certa[] =
	"416C696365"
	"BD1A5650179D79E03FCEE49D4C2BD5DD"
	"F54CE46D0CF11E4FF87BF7A890857FD0"
	"7AC6A60361E8C8173491686D461B2826"
	"190C2EDA5909054A9AB84D2AB9D99A90";

static const char _certb[] =
	"426F62"
	"CCEEF1A313A406649D15DA0A851D486A"
	"695B641B20611776252FFDCE39C71060"
	"7C9EA1F33C23D20DFCB8485A88BE6523"
	"A28ECC3215B47FA289D6C9BE1CE837C0";

/*
*******************************************************************************
Самотестирование: случайные числа сторон
*******************************************************************************
*/

static const char _bmqv_randa[] =
	"0A4E8298BE0839E46F19409F637F4415"
	"572251DD0D39284F0F0390D93BBCE9EC";

static const char _bmqv_randb[] =
	"0F51D91347617C20BD4AB07AEF4F26A1"
	"AD1362A8F9A3D42FBE1B8E6F1C88AAD5";

static const char _bsts_randa[] =
	"0A4E8298BE0839E46F19409F637F4415"
	"572251DD0D39284F0F0390D93BBCE9EC";

static const char _bsts_randb[] =
	"0F51D91347617C20BD4AB07AEF4F26A1"
	"AD1362A8F9A3D42FBE1B8E6F1C88AAD5";

static const char _bpace_randa[] =
	"AD1362A8F9A3D42FBE1B8E6F1C88AAD5"
	"0A4E8298BE0839E46F19409F637F4415"
	"572251DD0D39284F0F0390D93BBCE9EC";

static const char _bpace_randb[] =
	"0F51D91347617C20BD4AB07AEF4F26A1"
	"F81B29D571F6452FF8B2B97F57E18A58"
	"BC946FEE45EAB32B06FCAC23A33F422B";

/*
*******************************************************************************
Тестирование: сообщения сторон
*******************************************************************************
*/

static const char _bmqv_m1[] =
	"9B4EA669DABDF100A7D4B6E6EB76EE52"		// Vb
	"51912531F426750AAC8A9DBB51C54D8D"
	"6AB7DBF15FCBD768EE68A173F7B236EF"
	"C15A01E2AA6CD1FE98B947DA7B38A2A0";

static const char _bmqv_m2[] =
	"1D5A382B962D4ED06193258CA6DE535D"		// Va
	"8FD7FACB853171E932EF93B5EE800120"
	"03DBB7B5BD07036380BAFA47FCA7E6CA"
	"3F179EDDD1AE5086647909183628EDDC"
	"413B7E181BAFB337";						// Ta

static const char _bmqv_m3[] =
	"B800A2033AC7591B";						// Tb

static const char _bsts_m1[] =
	"9B4EA669DABDF100A7D4B6E6EB76EE52"		// Vb
	"51912531F426750AAC8A9DBB51C54D8D"
	"6AB7DBF15FCBD768EE68A173F7B236EF"
	"C15A01E2AA6CD1FE98B947DA7B38A2A0";

static const char _bsts_m2[] =
	"1D5A382B962D4ED06193258CA6DE535D"		// Va
	"8FD7FACB853171E932EF93B5EE800120"
	"03DBB7B5BD07036380BAFA47FCA7E6CA"
	"3F179EDDD1AE5086647909183628EDDC"
	"A994115F297D2FAD342A0AF54FCDA66E"		// Ya
	"1E6A30FE966662C43C2A73AFA3CADF69"
	"47344287CB200795616458678B76BA61"
	"924AD05D80BB81F53F8D5C4E0EF55EBD"
	"AFA674D7ECD74CB0609DE12BC0463670"
	"64059F011607DD18624074901F1C5A40"
	"94C006559F"
	"1306D68200087987";						// Ta

static const char _bsts_m3[] =
	"6D45B2E76AF24422ADC6D5D7A3CFA37F"		// Yb
	"DCB52F7E440222F1AACECB98BDED357B"
	"BD459DF0A3EE7A3EAFE0199CA5C4C072"
	"7C33909E4C322216F6F53E383A3727D8"
	"34B5D4F5C977FC3B7EBA6DCA55C0F1A5"
	"69BE3CD3464B13C388D0DAC3E6A82F9D"
	"2EF3D6"
	"CA7A5BAC4EB2910E";						// Tb

static const char _bpace_m1[] =
	"991E81690B4C687C86BFD11CEBDA2421";		// Yb

static const char _bpace_m2[] =
	"CE41B54DC13A28BDF74CEBD190881802"		// Ya
	"6B13ACBB086FB87618BCC2EF20A3FA89"		// Va
	"475654CB367E670A2441730B24B8AB31"
	"8209C81C9640C47A77B28E90AB9211A1"
	"DF21DE878191C314061E347C5125244F";

static const char _bpace_m3[] =
	"CD3D6487DC4EEB23456978186A069C71"		// Vb
	"375D75C2DF198BAD1E61EEA0DBBFF737"
	"3D1D9ED17A7AD460AA420FB11952D580"
	"78BC1CC9F408F2E258FDE97F22A44C6F"
	"28FD4859D78BA971";						// Tb

static const char _bpace_m4[] =
	"5D93FD9A7CB863AA";						// Ta

/*
*******************************************************************************
Проверка сертификата
*******************************************************************************
*/

static err_t bakeTestCertVal(octet* pubkey, const bign_params* params,
	const octet* data, size_t len)
{
	if (!memIsValid(params, sizeof(bign_params)) ||
		(params->l != 128 && params->l != 192 && params->l != 256) ||
		!memIsNullOrValid(pubkey, params->l / 2))
		return ERR_BAD_INPUT;
	if (!memIsValid(data, len) || len < params->l / 2)
		return ERR_BAD_CERT;
	if (pubkey)
		memCopy(pubkey, data + (len - params->l / 2), params->l / 2);
	return ERR_OK;
}

/*
*******************************************************************************
Проверка сообщений (после выполнения протокола)

\remark В функцию передается count эталонных сообщений в виде
шестнадцатеричных строк.
*******************************************************************************
*/

static err_t bakeTestMsgVal(size_t count, ...)
{
	va_list msgs;
	size_t i;
	// просмотреть сообщения... 
	va_start(msgs, count);
	for (i = 0; i < count; ++i)
	{
		// ...сравнить с эталонными
		char* msg = va_arg(msgs, char*);
		if (_msgs[i].len != strLen(msg) / 2 || !hexEq(_msgs[i].buf, msg))
			return FALSE;
	}
	return TRUE;
}

/*
*******************************************************************************
Самотестирование

-#	Выполняются тесты из приложения  к СТБ 34.101.66.
-#	Номера тестов соответствуют номерам таблиц приложения.
*******************************************************************************
*/

bool_t bakeTest()
{
	err_t codea;
	err_t codeb;
	bign_params params[1];
	octet randa[48];
	octet randb[48];
	octet echoa[64];
	octet echob[64];
	bake_settings settingsa[1];
	bake_settings settingsb[1];
	octet da[32];
	octet db[32];
	octet certdataa[5 /* Alice */ + 64 + 3 /* align */];
	octet certdatab[3 /* Bob */ + 64 + 5 /* align */];
	bake_cert certa[1];
	bake_cert certb[1];
	file_msg_st filea[1];
	file_msg_st fileb[1];
	const char pwd[] = "8086";
	octet keya[32];
	octet keyb[32];
	octet secret[32];
	octet iv[64];
	// подготовить память
	if (sizeof(echoa) < prngEcho_keep())
		return FALSE;
	// загрузить долговременные параметры
	if (bignParamsStd(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK)
		return FALSE;
	// задать настройки
	memSetZero(settingsa, sizeof(bake_settings));
	memSetZero(settingsb, sizeof(bake_settings));
	settingsa->kca = settingsa->kcb = TRUE;
	settingsb->kca = settingsb->kcb = TRUE;
	settingsa->rng = settingsb->rng = prngEchoStepR;
	settingsa->rng_state = echoa;
	settingsb->rng_state = echob;
	// загрузить личные ключи
	hexTo(da, _da);
	hexTo(db, _db);
	// загрузить сертификаты
	hexTo(certdataa, _certa);
	hexTo(certdatab, _certb);
	certa->data = certdataa;
	certa->len = strLen(_certa) / 2;
	certb->data = certdatab;
	certb->len = strLen(_certb) / 2;
	certa->val = certb->val = bakeTestCertVal;
	// тест Б.2: сеанс протокола
	hexTo(randa, _bmqv_randa);
	hexTo(randb, _bmqv_randb);
	fileMsgFlash();
	do
	{
		filea->i = filea->offset = 0;
		fileb->i = fileb->offset = 0;
		prngEchoStart(echoa, randa, strLen(_bmqv_randb) / 2);
		prngEchoStart(echob, randb, strLen(_bmqv_randb) / 2);
		codeb = bakeBMQVRunB(keyb, params, settingsb, db, certb, certa,
			fileMsgRead, fileMsgWrite, fileb);
		if (codeb != ERR_OK && codeb != ERR_FILE_NOT_FOUND)
			return FALSE;
		codea = bakeBMQVRunA(keya, params, settingsa, da, certa, certb,
			fileMsgRead, fileMsgWrite, filea);
		if (codea != ERR_OK && codea != ERR_FILE_NOT_FOUND)
			return FALSE;
	}
	while (codea == ERR_FILE_NOT_FOUND || codeb == ERR_FILE_NOT_FOUND);
	// тест Б.2: общие ключи
	if (!memEq(keya, keyb, 32) ||
		!hexEq(keya,
			"C6F86D0E468D5EF1A9955B2EE0CF0581"
			"050C81D1B47727092408E863C7EEB48C"))
		return FALSE;
	// тест Б.2: сообщения
	if (!bakeTestMsgVal(3, _bmqv_m1, _bmqv_m2, _bmqv_m3))
		return FALSE;
	// тест Б.3: сеанс протокола
	hexTo(randa, _bsts_randa);
	hexTo(randb, _bsts_randb);
	fileMsgFlash();
	do
	{
		filea->i = filea->offset = 0;
		fileb->i = fileb->offset = 0;
		prngEchoStart(echoa, randa, strLen(_bsts_randb) / 2);
		prngEchoStart(echob, randb, strLen(_bsts_randb) / 2);
		codeb = bakeBSTSRunB(keyb, params, settingsb, db, certb,
			bakeTestCertVal, fileMsgRead, fileMsgWrite, fileb);
		if (codeb != ERR_OK && codeb != ERR_FILE_NOT_FOUND)
			return FALSE;
		codea = bakeBSTSRunA(keya, params, settingsa, da, certa,
			bakeTestCertVal, fileMsgRead, fileMsgWrite, filea);
		if (codea != ERR_OK && codea != ERR_FILE_NOT_FOUND)
			return FALSE;
	}
	while (codea == ERR_FILE_NOT_FOUND || codeb == ERR_FILE_NOT_FOUND);
	// тест Б.3: общие ключи
	if (!memEq(keya, keyb, 32) ||
		!hexEq(keya,
			"78EF2C56BD6DA2116BB5BEE80CEE5C05"
			"394E7609183CF7F76DF0C2DCFB25C4AD"))
		return FALSE;
	// тест Б.3: сообщения
	if (!bakeTestMsgVal(3, _bsts_m1, _bsts_m2, _bsts_m3))
		return FALSE;
	// тест Б.4: сеанс протокола
	hexTo(randa, _bpace_randa);
	hexTo(randb, _bpace_randb);
	fileMsgFlash();
	do
	{
		filea->i = filea->offset = 0;
		fileb->i = fileb->offset = 0;
		prngEchoStart(echoa, randa, strLen(_bpace_randb) / 2);
		prngEchoStart(echob, randb, strLen(_bpace_randb) / 2);
		codeb = bakeBPACERunB(keyb, params, settingsb, (const octet*)pwd,
			strLen(pwd), fileMsgRead, fileMsgWrite, fileb);
		if (codeb != ERR_OK && codeb != ERR_FILE_NOT_FOUND)
			return FALSE;
		codea = bakeBPACERunA(keya, params, settingsa, (const octet*)pwd,
			strLen(pwd), fileMsgRead, fileMsgWrite, filea);
		if (codea != ERR_OK && codea != ERR_FILE_NOT_FOUND)
			return FALSE;
	}
	while (codea == ERR_FILE_NOT_FOUND || codeb == ERR_FILE_NOT_FOUND);
	if (!memEq(keya, keyb, 32) ||
		!hexEq(keya,
			"DAC4D8F411F9C523D28BBAAB32A5270E"
			"4DFA1F0F757EF8E0F30AF08FBDE1E7F4"))
		return FALSE;
	// тест Б.4: сеанс протокола
	if (!bakeTestMsgVal(4, _bpace_m1, _bpace_m2, _bpace_m3, _bpace_m4))
		return FALSE;
	// тест bakeKDF (по данным из теста Б.4)
	hexTo(secret, 
		"723356E335ED70620FFB1842752092C3"
		"2603EB666040920587D800575BECFC42");
	hexTo(iv, 
		"6B13ACBB086FB87618BCC2EF20A3FA89"
		"475654CB367E670A2441730B24B8AB31"
		"CD3D6487DC4EEB23456978186A069C71"
		"375D75C2DF198BAD1E61EEA0DBBFF737");
	if (bakeKDF(keya, secret, 32, iv, 64, 0) != ERR_OK ||
		bakeKDF(keyb, secret, 32, iv, 64, 1) != ERR_OK ||
		!hexEq(keya,
			"DAC4D8F411F9C523D28BBAAB32A5270E"
			"4DFA1F0F757EF8E0F30AF08FBDE1E7F4") ||
		!hexEq(keyb,
			"54AC058284D679CF4C47D3D72651F3E4"
			"EF0D61D1D0ED5BAF8FF30B8924E599D8"))
		return FALSE;
	// тест bakeSWU (по данным из теста Б.4)
	hexTo(secret, 
		"AD1362A8F9A3D42FBE1B8E6F1C88AAD5"
		"0F51D91347617C20BD4AB07AEF4F26A1");
	if (bakeSWU(iv, params, secret) != ERR_OK ||
		!hexEq(iv,
			"014417D3355557317D2E2AB6D0875487"
			"8D19E8D97B71FDC95DBB2A9B894D16D7"
			"7704A0B5CAA9CDA10791E4760671E105"
			"0DDEAB7083A7458447866ADB01473810"))
		return FALSE;
	// все нормально
	return TRUE;
}
