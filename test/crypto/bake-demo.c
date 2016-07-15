/*
*******************************************************************************
\file bake-demo.c
\brief Demo for STB 34.101.66 (bake)
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2014.05.03
\version 2016.07.15
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/err.h>
#include <bee2/core/mem.h>
#include <bee2/core/hex.h>
#include <bee2/core/prng.h>
#include <bee2/core/str.h>
#include <bee2/core/u16.h>
#include <bee2/core/util.h>
#include <bee2/crypto/bake.h>

/*
*******************************************************************************
Проверочный канал связи

Проверочный канал связи задается буфером памяти, разбитым на пакеты. Пакет
описывает отдельное сообщение протокола. Пакет имеет формат len || frame,
где len -- длина, заданная двумя октетами по правилам little-endian,
frame -- содержимое пакета, состоящее из len октетов.

Чтение из канала -- это чтение пакета или его части.
Запись в канал --- это сравнение записываемого сообщения с текущим пакетом.
*******************************************************************************
*/

typedef struct
{
	octet* data;			/* буфер памяти */
	size_t data_len;		/* длина буфера */
	octet* frame;			/* текущий пакет */
	size_t frame_len;		/* длина текущего пакета */
	size_t frame_offset;	/* смещение в текущем пакете */
} file_st;

static err_t fileCreate(void* file, void* data, size_t data_len)
{
	file_st* f = (file_st*)file;
	u16 len;
	// pre
	if (!memIsValid(f, sizeof(file_st)) ||
		!memIsValid(data, data_len))
		return ERR_BAD_INPUT;
	// запомнить буфер
	f->data = data;
	f->data_len = data_len;
	// нет пакетов?
	if (data_len < 2)
	{
		f->frame = 0;
		f->frame_len = f->frame_offset = 0;
	}
	// найти первый пакет
	else
	{
		u16From(&len, data, 2);
		f->frame_len = (size_t)len;
		f->frame = f->data + 2;
		f->frame_offset = 0;
		// выход за границы?
		if (f->frame + f->frame_len > f->data + f->data_len)
			return ERR_BAD_FORMAT;
	}
	// все нормально
	return ERR_OK;
}

static err_t fileWrite(size_t* written, const void* buf, size_t count,
	void* file)
{
	file_st* f = (file_st*)file;
	u16 len;
	// pre
	ASSERT(memIsValid(f, sizeof(file_st)));
	ASSERT(memIsValid(buf, count));
	ASSERT(memIsValid(written, sizeof(size_t)));
	// конец файла?
	// запись не с начала пакета?
	// отличаются длины пакета и сообщения?
	// отличается содержимое?
	if (f->frame == 0 ||
		f->frame_offset != 0 ||
		f->frame_len != count ||
		!memEq(f->frame, buf, count))
		return ERR_FILE_WRITE;
	// к следующему пакету
	f->frame += f->frame_len;
	if (f->frame + 2 >= f->data + f->data_len)
	{
		f->frame = 0;
		f->frame_len = f->frame_offset = 0;
	}
	else
	{
		u16From(&len, f->frame, 2);
		f->frame_len = (size_t)len;
		f->frame += 2;
		f->frame_offset = 0;
		// выход за границы?
		if (f->frame + f->frame_len > f->data + f->data_len)
			return ERR_BAD_FORMAT;
	}
	// все нормально
	*written = count;
	return ERR_OK;
}

static err_t fileRead(size_t* read, void* buf, size_t count, void* file)
{
	file_st* f = (file_st*)file;
	u16 len;
	err_t code;
	// pre
	ASSERT(memIsValid(f, sizeof(file_st)));
	ASSERT(memIsValid(buf, count));
	ASSERT(memIsValid(read, sizeof(size_t)));
	// достигнут конец файла?
	if (f->frame == 0)
	{
		*read = 0;
		return ERR_MAX;
	}
	// достигается конец файла?
	if (f->frame_offset + count > f->frame_len)
	{
		*read = f->frame_len - f->frame_offset;
		memCopy(buf, f->frame + f->frame_offset, *read);
		code = ERR_MAX;
	}
	// обычное чтение
	else
	{
		*read = count;
		memCopy(buf, f->frame + f->frame_offset, *read);
		code = ERR_OK;
	}
	// к следующему пакету
	f->frame += f->frame_len;
	if (f->frame + 2 >= f->data + f->data_len)
	{
		f->frame = 0;
		f->frame_len = f->frame_offset = 0;
	}
	else
	{
		u16From(&len, f->frame, 2);
		f->frame_len = (size_t)len;
		f->frame += 2;
		f->frame_offset = 0;
		// выход за границы?
		if (f->frame + f->frame_len > f->data + f->data_len)
			return ERR_BAD_FORMAT;
	}
	// все нормально
	return code;
}

/*
*******************************************************************************
Тестирование: таблица Б.1
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
Тестирование: случайные числа сторон
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

static const char _bmqv_data[] =
	"4000"									// M1
	"9B4EA669DABDF100A7D4B6E6EB76EE52"		// M1::Vb
	"51912531F426750AAC8A9DBB51C54D8D"
	"6AB7DBF15FCBD768EE68A173F7B236EF"
	"C15A01E2AA6CD1FE98B947DA7B38A2A0"
	"4800"									// M2
	"1D5A382B962D4ED06193258CA6DE535D"		// M2::Va
	"8FD7FACB853171E932EF93B5EE800120"
	"03DBB7B5BD07036380BAFA47FCA7E6CA"
	"3F179EDDD1AE5086647909183628EDDC"
	"413B7E181BAFB337"						// M2::Ta
	"0800"									// M3
	"B800A2033AC7591B";						// M3::Tb

static const char _bsts_data[] =
	"4000"									// M1
	"9B4EA669DABDF100A7D4B6E6EB76EE52"		// M1::Vb
	"51912531F426750AAC8A9DBB51C54D8D"
	"6AB7DBF15FCBD768EE68A173F7B236EF"
	"C15A01E2AA6CD1FE98B947DA7B38A2A0"
	"AD00"									// M2
	"1D5A382B962D4ED06193258CA6DE535D"		// M2::Va
	"8FD7FACB853171E932EF93B5EE800120"
	"03DBB7B5BD07036380BAFA47FCA7E6CA"
	"3F179EDDD1AE5086647909183628EDDC"
	"A994115F297D2FAD342A0AF54FCDA66E"		// M2::Ya
	"1E6A30FE966662C43C2A73AFA3CADF69"
	"47344287CB200795616458678B76BA61"
	"924AD05D80BB81F53F8D5C4E0EF55EBD"
	"AFA674D7ECD74CB0609DE12BC0463670"
	"64059F011607DD18624074901F1C5A40"
	"94C006559F"
	"1306D68200087987"						// M2::Ta
	"6B00"									// M3
	"6D45B2E76AF24422ADC6D5D7A3CFA37F"		// M3::Yb
	"DCB52F7E440222F1AACECB98BDED357B"
	"BD459DF0A3EE7A3EAFE0199CA5C4C072"
	"7C33909E4C322216F6F53E383A3727D8"
	"34B5D4F5C977FC3B7EBA6DCA55C0F1A5"
	"69BE3CD3464B13C388D0DAC3E6A82F9D"
	"2EF3D6"
	"CA7A5BAC4EB2910E";						// Tb

static const char _bpace_data[] =
	"1000"									// M1
	"991E81690B4C687C86BFD11CEBDA2421"		// M1::Yb
	"5000"									// M2
	"CE41B54DC13A28BDF74CEBD190881802"		// M2::Ya
	"6B13ACBB086FB87618BCC2EF20A3FA89"		// M2::Va
	"475654CB367E670A2441730B24B8AB31"
	"8209C81C9640C47A77B28E90AB9211A1"
	"DF21DE878191C314061E347C5125244F"
	"4800"									// M3
	"CD3D6487DC4EEB23456978186A069C71"		// M3::Vb
	"375D75C2DF198BAD1E61EEA0DBBFF737"
	"3D1D9ED17A7AD460AA420FB11952D580"
	"78BC1CC9F408F2E258FDE97F22A44C6F"
	"28FD4859D78BA971"						// M3::Tb
	"0800"									// M4
	"5D93FD9A7CB863AA";						// M4::Ta
/*
*******************************************************************************
Проверка сертификата
*******************************************************************************
*/

static err_t certVal(octet* pubkey, const bign_params* params,
	const octet* data, size_t len)
{
	if (!memIsValid(params, sizeof(bign_params)) ||
		(params->l != 128 && params->l != 192 && params->l != 256) ||
		!memIsNullOrValid(pubkey, params->l / 2))
		return ERR_BAD_INPUT;
	if (!memIsValid(data, len) ||
		len < params->l / 2)
		return ERR_BAD_CERT;
	if (pubkey)
		memCopy(pubkey, data + (len - params->l / 2), params->l / 2);
	return ERR_OK;
}

/*
*******************************************************************************
Тестирование

-#	Выполняются тесты из приложения  к СТБ 34.101.66.
-#	Номера тестов соответствуют номерам таблиц приложения.
*******************************************************************************
*/

bool_t bakeDemo()
{
	bign_params params[1];
	octet randa[48];
	octet randb[48];
	octet echoa[64];
	octet echob[64];
	bake_settings settingsa[1];
	bake_settings settingsb[1];
	octet da[32];
	octet db[32];
	octet certdataa[5 + 64];
	octet certdatab[3 + 64];
	bake_cert certa[1];
	bake_cert certb[1];
	octet file_data[1024];
	file_st filea[1];
	file_st fileb[1];
	const char pwd[] = "8086";
	octet keya[32];
	octet keyb[32];
	// загрузить долговременные параметры
	if (bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1") != ERR_OK)
	 return FALSE;
	// настроить генераторы
	ASSERT(prngEcho_keep() <= sizeof(echoa));
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
	certa->val = certb->val = certVal;
	// тест Б.2
	hexTo(randa, _bmqv_randa);
	hexTo(randb, _bmqv_randb);
	ASSERT(sizeof(file_data) >= strlen(_bmqv_data) / 2);
	hexTo(file_data, _bmqv_data);
	if (fileCreate(filea, file_data, strlen(_bmqv_data) / 2) != ERR_OK ||
		fileCreate(fileb, file_data, strlen(_bmqv_data) / 2) != ERR_OK)
		return FALSE;
	prngEchoStart(echoa, randa, strLen(_bmqv_randb) / 2);
	prngEchoStart(echob, randb, strLen(_bmqv_randb) / 2);
	if (bakeBMQVRunB(keyb, params, settingsb, db, certb, certa,
			fileRead, fileWrite, fileb) != ERR_OK ||
		bakeBMQVRunA(keya, params, settingsa, da, certa, certb,
			fileRead, fileWrite, filea))
			return FALSE;
	if (!memEq(keya, keyb, 32) ||
		!hexEq(keya,
			"C6F86D0E468D5EF1A9955B2EE0CF0581"
			"050C81D1B47727092408E863C7EEB48C"))
		return FALSE;
	// тест Б.3
	hexTo(randa, _bsts_randa);
	hexTo(randb, _bsts_randb);
	ASSERT(sizeof(file_data) >= strlen(_bsts_data) / 2);
	hexTo(file_data, _bsts_data);
	if (fileCreate(filea, file_data, strlen(_bsts_data) / 2) != ERR_OK ||
		fileCreate(fileb, file_data, strlen(_bsts_data) / 2) != ERR_OK)
		return FALSE;
	prngEchoStart(echoa, randa, strLen(_bsts_randb) / 2);
	prngEchoStart(echob, randb, strLen(_bsts_randb) / 2);
	if (bakeBSTSRunB(keyb, params, settingsb, db, certb, certVal,
			fileRead, fileWrite, fileb) != ERR_OK ||
		bakeBSTSRunA(keya, params, settingsa, da, certa, certVal,
			fileRead, fileWrite, filea))
			return FALSE;
	if (!memEq(keya, keyb, 32) ||
		!hexEq(keya,
			"78EF2C56BD6DA2116BB5BEE80CEE5C05"
			"394E7609183CF7F76DF0C2DCFB25C4AD"))
		return FALSE;
	// тест Б.4
	hexTo(randa, _bpace_randa);
	hexTo(randb, _bpace_randb);
	ASSERT(sizeof(file_data) >= strlen(_bsts_data) / 2);
	hexTo(file_data, _bpace_data);
	if (fileCreate(filea, file_data, strlen(_bpace_data) / 2) != ERR_OK ||
		fileCreate(fileb, file_data, strlen(_bpace_data) / 2) != ERR_OK)
		return FALSE;
	prngEchoStart(echoa, randa, strLen(_bpace_randb) / 2);
	prngEchoStart(echob, randb, strLen(_bpace_randb) / 2);
	if (bakeBPACERunB(keyb, params, settingsb, (octet*)pwd, strLen(pwd),
			fileRead, fileWrite, fileb) != ERR_OK ||
		bakeBPACERunA(keya, params, settingsa, (octet*)pwd, strLen(pwd),
			fileRead, fileWrite, filea))
			return FALSE;
	if (!memEq(keya, keyb, 32) ||
		!hexEq(keya,
			"DAC4D8F411F9C523D28BBAAB32A5270E"
			"4DFA1F0F757EF8E0F30AF08FBDE1E7F4"))
		return FALSE;
	// все нормально
	return TRUE;
}
