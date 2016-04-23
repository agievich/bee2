/*
*******************************************************************************
\file dstu.c
\brief DSTU 4145-2002 (Ukraine): digital signature algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.04.27
\version 2016.04.22
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/blob.h"
#include "bee2/core/err.h"
#include "bee2/core/mem.h"
#include "bee2/core/str.h"
#include "bee2/core/util.h"
#include "bee2/crypto/dstu.h"
#include "bee2/math/ec2.h"
#include "bee2/math/gf2.h"
#include "bee2/math/ww.h"
#include "bee2/math/zz.h"

/*
*******************************************************************************
Глубина стека

Высокоуровневые функции сообщают о потребностях в стековой памяти через 
функции интерфейса _dstu_deep_i. Потребности не должны учитывать память для 
размещения описаний базового поля и эллиптической кривой.
*******************************************************************************
*/

typedef size_t (*_dstu_deep_i)(
	size_t n,					/* размерность (в машинных словах) */
	size_t f_deep,				/* глубина стека базового поля */
	size_t ec_d,				/* число проективных координат */
	size_t ec_deep				/* глубина стека эллиптической кривой */
);

/*
*******************************************************************************
Стандартные параметры: dstu_163pb 
[базовая точка взята из приложения Б]
*******************************************************************************
*/

static const char _curve163pb_name[] = "1.2.804.2.1.1.1.1.3.1.1.1.2.0";

static u16 _curve163pb_p[4] = {163, 7, 6, 3};

static octet _curve163pb_A = 1;

static octet _curve163pb_B[] = {
	0x21, 0x5D, 0x45, 0xC1, 0x19, 0x8A, 0x63, 0x5E,
	0x92, 0x03, 0xB4, 0x0A, 0x21, 0xC8, 0x2D, 0x2A,
	0x46, 0x08, 0x61, 0xFF, 0x05,
};

static octet _curve163pb_n[] = {
	0x4D, 0xF1, 0xBC, 0x39, 0x2D, 0x26, 0xE2, 0x2B,
	0xC1, 0xBE, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04,
};

static octet _curve163pb_c = 2;

static octet _curve163pb_P[] = {
// x
	0x20, 0x04, 0x54, 0x8C, 0x5C, 0x88, 0x74, 0xFE,
	0xAF, 0x01, 0xFF, 0xF9, 0x7D, 0xC2, 0x3A, 0xA9,
	0x93, 0x7F, 0x86, 0x2D, 0x07,
// y
	0x9B, 0xFD, 0xC3, 0xAD, 0x22, 0x11, 0xB8, 0x4A,
	0x5F, 0x9D, 0x59, 0xC5, 0x97, 0x2B, 0x85, 0x47,
	0x39, 0x9C, 0x4A, 0x22, 0x00,
};

/*
*******************************************************************************
Стандартные параметры: dstu_167pb
*******************************************************************************
*/

static const char _curve167pb_name[] = "1.2.804.2.1.1.1.1.3.1.1.1.2.1";

static u16 _curve167pb_p[4] = {167, 6};

static octet _curve167pb_A = 1;

static octet _curve167pb_B[] = {
	0xAC, 0x7D, 0x82, 0x5A, 0x31, 0xA4, 0xF1, 0x30,
	0x09, 0x8A, 0x51, 0x20, 0x9F, 0x75, 0x11, 0x08,
	0x23, 0xEB, 0xCE, 0xE3, 0x6E,
};

static octet _curve167pb_n[] = {
	0x1F, 0x70, 0xF7, 0x9F, 0xF2, 0xD7, 0xC7, 0xBC,
	0x2E, 0xB1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x3F,
};

static octet _curve167pb_c = 2;

/*
*******************************************************************************
Стандартные параметры: dstu_173pb
*******************************************************************************
*/

static const char _curve173pb_name[] = "1.2.804.2.1.1.1.1.3.1.1.1.2.2";

static u16 _curve173pb_p[4] = {173, 10, 2, 1};

static octet _curve173pb_A = 0;

static octet _curve173pb_B[] = {
	0xD9, 0x37, 0xB4, 0x6F, 0x6B, 0x8F, 0x27, 0xBB,
	0x3B, 0x85, 0xF6, 0xDD, 0x6E, 0xC1, 0x2F, 0xDB,
	0x99, 0x04, 0xC8, 0x76, 0x85, 0x10,
};

static octet _curve173pb_n[] = {
	0x31, 0x28, 0xBB, 0x25, 0x38, 0x6E, 0x60, 0x67,
	0x4E, 0x9B, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
};

static octet _curve173pb_c = 4;

/*
*******************************************************************************
Стандартные параметры: dstu_179pb
*******************************************************************************
*/

static const char _curve179pb_name[] = "1.2.804.2.1.1.1.1.3.1.1.1.2.3";

static u16 _curve179pb_p[4] = {179, 4, 2, 1};

static octet _curve179pb_A = 1;

static octet _curve179pb_B[] = {
	0x10, 0xB7, 0xBE, 0x72, 0x45, 0x18, 0x04, 0x2D,
	0xE3, 0x41, 0xA3, 0x07, 0xDD, 0x88, 0x2F, 0x6F,
	0x43, 0x26, 0x65, 0x85, 0xE0, 0xA6, 0x04,
};

static octet _curve179pb_n[] = {
	0xEF, 0x36, 0x42, 0xB6, 0x5A, 0xFE, 0x35, 0x04,
	0x96, 0x81, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x03,
};

static octet _curve179pb_c = 2;

/*
*******************************************************************************
Стандартные параметры: dstu_191pb
*******************************************************************************
*/

static const char _curve191pb_name[] = "1.2.804.2.1.1.1.1.3.1.1.1.2.4";

static u16 _curve191pb_p[4] = {191, 9};

static octet _curve191pb_A = 1;

static octet _curve191pb_B[] = {
	0x03, 0xFC, 0xFE, 0x50, 0x27, 0x48, 0xE0, 0x27,
	0xFF, 0x81, 0x49, 0x6B, 0x8B, 0x0E, 0x89, 0xD5,
	0xC4, 0x2E, 0x90, 0x02, 0x21, 0x6E, 0xC8, 0x7B
};

static octet _curve191pb_n[] = {
	0x4F, 0x47, 0xF7, 0x88, 0x67, 0xBC, 0xDA, 0xC1,
	0xCA, 0x79, 0xA7, 0x69, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
};

static octet _curve191pb_c = 2;

/*
*******************************************************************************
Стандартные параметры: dstu_233pb
*******************************************************************************
*/

static const char _curve233pb_name[] = "1.2.804.2.1.1.1.1.3.1.1.1.2.5";

static u16 _curve233pb_p[4] = {233, 9, 4, 1};

static octet _curve233pb_A = 1;

static octet _curve233pb_B[] = {
	0x2C, 0x4D, 0x45, 0xCE, 0x6E, 0x93, 0xAA, 0x26,
	0x03, 0x8A, 0x3B, 0xDD, 0xF5, 0x4E, 0xD5, 0x1B,
	0xA2, 0x64, 0x7E, 0xCF, 0xC7, 0x34, 0x55, 0x67,
	0x95, 0x50, 0xB1, 0x73, 0x69, 0x00,
};

static octet _curve233pb_n[] = {
	0xD7, 0xE0, 0xCF, 0x03, 0x26, 0x1D, 0x03, 0x22,
	0x69, 0x8A, 0x2F, 0xE7, 0x74, 0xE9, 0x13, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

static octet _curve233pb_c = 2;

/*
*******************************************************************************
Стандартные параметры: dstu_257pb
*******************************************************************************
*/

static const char _curve257pb_name[] = "1.2.804.2.1.1.1.1.3.1.1.1.2.6";

static u16 _curve257pb_p[4] = {257, 12};

static octet _curve257pb_A = 0;

static octet _curve257pb_B[] = {
	0x10, 0xBE, 0xE3, 0xDB, 0x6A, 0xEA, 0x9E, 0x1F,
	0x86, 0x57, 0x8C, 0x45, 0xC1, 0x25, 0x94, 0xFF,
	0x94, 0x23, 0x94, 0xA7, 0xD7, 0x38, 0xF9, 0x18,
	0x7E, 0x65, 0x15, 0x01, 0x72, 0x94, 0xF4, 0xCE,
	0x01,
};

static octet _curve257pb_n[] = {
	0x0D, 0x47, 0x7D, 0x90, 0x14, 0x77, 0xE1, 0xD3,
	0x87, 0xE9, 0x82, 0xF1, 0x3A, 0x21, 0x59, 0x67,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
};

static octet _curve257pb_c = 4;

/*
*******************************************************************************
Стандартные параметры: dstu_307pb
*******************************************************************************
*/

static const char _curve307pb_name[] = "1.2.804.2.1.1.1.1.3.1.1.1.2.7";

static u16 _curve307pb_p[4] = {307, 8, 4, 2};

static octet _curve307pb_A = 1;

static octet _curve307pb_B[] = {
	0xBB, 0x68, 0x49, 0x90, 0x86, 0x01, 0xC9, 0xBD,
	0x90, 0x60, 0x8B, 0xF1, 0x0D, 0x05, 0x41, 0xE2,
	0xE2, 0xE2, 0x99, 0xC5, 0xC0, 0x96, 0x42, 0x4F,
	0xE9, 0x3D, 0x6D, 0x6C, 0x5E, 0x4B, 0x05, 0xB5,
	0x66, 0x36, 0xD5, 0xF7, 0xC7, 0x93, 0x03,
};

static octet _curve307pb_n[] = {
	0xB7, 0xB7, 0x22, 0x40, 0x60, 0xD4, 0x88, 0xA5,
	0xBB, 0x0F, 0x39, 0x0D, 0xA7, 0x5D, 0x82, 0xF3,
	0xC2, 0x79, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x03,
};

static octet _curve307pb_c = 2;

/*
*******************************************************************************
Стандартные параметры: dstu_367pb
*******************************************************************************
*/

static const char _curve367pb_name[] = "1.2.804.2.1.1.1.1.3.1.1.1.2.8";

static u16 _curve367pb_p[4] = {367, 21};

static octet _curve367pb_A = 1;

static octet _curve367pb_B[] = {
	0x36, 0x51, 0x99, 0x56, 0x7B, 0x43, 0x55, 0x97,
	0xA7, 0x79, 0x4C, 0x39, 0x92, 0x3D, 0xF9, 0xB8,
	0xDA, 0xCA, 0x42, 0xFE, 0x2A, 0x0C, 0x4B, 0xA6,
	0xA4, 0x6A, 0xBF, 0x47, 0x6B, 0x55, 0x47, 0x44,
	0x65, 0xD5, 0x7A, 0x62, 0xD1, 0xF3, 0xA6, 0xB7,
	0xB0, 0x42, 0xD2, 0x8A, 0xFC, 0x43,
};

static octet _curve367pb_n[] = {

	0x49, 0x2D, 0x9B, 0x04, 0x44, 0xEF, 0x45, 0x22,
	0x81, 0xE8, 0x8C, 0xD2, 0x8F, 0x42, 0x22, 0x4F,
	0x82, 0xFA, 0xA3, 0x75, 0x0B, 0x30, 0x9C, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
};

static octet _curve367pb_c = 2;

/*
*******************************************************************************
Стандартные параметры: dstu_431pb
*******************************************************************************
*/

static const char _curve431pb_name[] = "1.2.804.2.1.1.1.1.3.1.1.1.2.9";

static u16 _curve431pb_p[4] = {431, 5, 3, 1};

static octet _curve431pb_A = 1;

static octet _curve431pb_B[] = {
	0xF3, 0xCA, 0x40, 0xC6, 0x69, 0xA4, 0xDA, 0x17,
	0x31, 0x49, 0xCA, 0x12, 0xC3, 0x2D, 0xAE, 0x18,
	0x6B, 0x53, 0xAC, 0x6B, 0xC6, 0x36, 0x59, 0x97,
	0xDE, 0xAE, 0xAE, 0x8A, 0xD2, 0xD8, 0x88, 0xF9,
	0xBF, 0xD5, 0x34, 0x01, 0x69, 0x4E, 0xF9, 0xC4,
	0x27, 0x3D, 0x8C, 0xFE, 0x6D, 0xC2, 0x8F, 0x70,
	0x6A, 0x0F, 0x49, 0x10, 0xCE, 0x03,
};

static octet _curve431pb_n[] = {
	0xCF, 0x04, 0x05, 0x11, 0x95, 0x7A, 0x0C, 0xD9,
	0x80, 0xAF, 0xCB, 0x1F, 0x8A, 0xAA, 0x81, 0x2F,
	0xF0, 0x24, 0xA7, 0xC0, 0xA8, 0x09, 0x80, 0x45,
	0x75, 0x31, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F,
};

static octet _curve431pb_c = 2;

/*
*******************************************************************************
Загрузка стандартных параметров
*******************************************************************************
*/

#define _LOAD_NAMED_PARAMS(params, name)\
	memCopy((params)->p, _##name##_p, sizeof(_##name##_p));\
	(params)->A = _##name##_A;\
	memCopy((params)->B, _##name##_B, sizeof(_##name##_B));\
	memCopy((params)->n, _##name##_n, sizeof(_##name##_n));\
	(params)->c = _##name##_c;\


err_t dstuStdParams(dstu_params* params, const char* name)
{
	if (!memIsValid(params, sizeof(dstu_params)))
		return ERR_BAD_INPUT;
	memSetZero(params, sizeof(dstu_params));
	if (strEq(name, _curve163pb_name))
	{
		_LOAD_NAMED_PARAMS(params, curve163pb);
		memCopy(params->P, _curve163pb_P, sizeof(_curve163pb_P));
		return ERR_OK;
	}
	if (strEq(name, _curve167pb_name))
	{
		_LOAD_NAMED_PARAMS(params, curve167pb);
		return ERR_OK;
	}
	if (strEq(name, _curve173pb_name))
	{
		_LOAD_NAMED_PARAMS(params, curve173pb);
		return ERR_OK;
	}
	if (strEq(name, _curve179pb_name))
	{
		_LOAD_NAMED_PARAMS(params, curve179pb);
		return ERR_OK;
	}
	if (strEq(name, _curve191pb_name))
	{
		_LOAD_NAMED_PARAMS(params, curve191pb);
		return ERR_OK;
	}
	if (strEq(name, _curve233pb_name))
	{
		_LOAD_NAMED_PARAMS(params, curve233pb);
		return ERR_OK;
	}
	if (strEq(name, _curve257pb_name))
	{
		_LOAD_NAMED_PARAMS(params, curve257pb);
		return ERR_OK;
	}
	if (strEq(name, _curve307pb_name))
	{
		_LOAD_NAMED_PARAMS(params, curve307pb);
		return ERR_OK;
	}
	if (strEq(name, _curve367pb_name))
	{
		_LOAD_NAMED_PARAMS(params, curve367pb);
		return ERR_OK;
	}
	if (strEq(name, _curve431pb_name))
	{
		_LOAD_NAMED_PARAMS(params, curve431pb);
		return ERR_OK;
	}
	return ERR_FILE_NOT_FOUND;
}

/*
*******************************************************************************
Создание описания эллиптической кривой

По долговременным параметрам params формируется описание pec эллиптической
кривой. Указатель *pec является одновременно началом фрагмента памяти, 
в котором размещается состояние и стек. Длина фрагмента определяется с учетом 
потребностей deep и размерностей dims.
\pre Указатель pec корректен.
\return ERR_OK, если описание успешно создано, и код ошибки в противном 
случае.
\remark Запрошенная память начинается по адресу objEnd(*pec, void).
\remark Проводится минимальная проверка параметров, обеспечивающая 
работоспособность высокоуровневых функций.
*******************************************************************************
*/

static err_t _dstuCreateEc(
	ec_o** pec,						/* [out] описание эллиптической кривой */
	const dstu_params* params,		/* [in] долговременные параметры */
	_dstu_deep_i deep				/* [in] потребности в стековой памяти */
)
{
	// размерности
	size_t m;
	size_t n;
	size_t f_keep;
	size_t f_deep;
	size_t ec_d;
	size_t ec_keep;
	size_t ec_deep;
	// состояние
	void* state;	
	size_t* p;			/* описание многочлена */
	qr_o* f;			/* поле */
	octet* A;			/* коэффициент A */
	ec_o* ec;			/* кривая */
	void* stack;
	// pre
	ASSERT(memIsValid(pec, sizeof(*pec)));
	// минимальная проверка входных данных
	if (!memIsValid(params, sizeof(dstu_params)) ||
		(m = params->p[0]) < 160 || m > 509 || 
		params->A > 1)
		return ERR_BAD_PARAMS;
	// определить размерности
	n = W_OF_B(m);
	f_keep = gf2Create_keep(m);
	f_deep = gf2Create_deep(m);
	ec_d = 3;
	ec_keep = ec2CreateLD_keep(n);
	ec_deep = ec2CreateLD_deep(n, f_deep);
	// создать состояние
	state = blobCreate(
		f_keep + ec_keep +
		utilMax(4,
			4 * sizeof(size_t) + f_deep,
			O_OF_B(m) + ec_deep,
			ecCreateGroup_deep(f_deep),
			deep(n, f_deep, ec_d, ec_deep)));
	if (state == 0)
		return ERR_OUTOFMEMORY;
	// создать поле
	f = (qr_o*)((octet*)state + ec_keep);
	p = (size_t*)((octet*)f + f_keep);
	p[0] = params->p[0];
	p[1] = params->p[1];
	p[2] = params->p[2];
	p[3] = params->p[3];
	stack = p + 4;
	if (!gf2Create(f, p, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// создать кривую и группу
	ec = (ec_o*)state;
	A = (octet*)p;
	A[0] = params->A;
	memSetZero(A + 1, f->no - 1);
	stack = A + f->no;
	if (!ec2CreateLD(ec, f, A, params->B, stack) ||
		!ecCreateGroup(ec, params->P, params->P + ec->f->no, params->n, 
			ec->f->no, params->c, stack))
	{
		blobClose(state);
		return ERR_BAD_PARAMS;
	}
	// присоединить f к ec
	objAppend(ec, f, 0);
	// все нормально
	*pec = ec;
	return ERR_OK;
}

/*
*******************************************************************************
Закрытие описания эллиптической кривой
*******************************************************************************
*/

void _dstuCloseEc(ec_o* ec)
{
	blobClose(ec);
}

/*
*******************************************************************************
Проверка параметров

В ДСТУ требуется, чтобы
1) A \in {0, 1},
2) B != 0,
3) order >= 2^160,
4) order >= 4(\floor{\sqrt{2^m}} + 1),
5) кривая является безопасной с MOV-порогом 32.

Условие 1) проверяется в функции _dstuCreateEc().
Условие 2) проверяется в функции ec2IsValid().
Условие 3) проверяется непосредственно.
Условие 4) следует из границы Хассе
	order * cofactor >= 2^m + 1 - 2^{m/2}
при малом cofactor и достаточно большом m.
Граница Хассе проверяется в функции ec2IsValid().

Дополнительно проверяется, что базовая точка лежит на кривой и имеет
порядок order.
*******************************************************************************
*/

static size_t _dstuValParams_deep(size_t n, size_t f_deep, size_t ec_d, 
	size_t ec_deep)
{
	return utilMax(4,
			ec2IsValid_deep(n),
			ec2SeemsValidGroup_deep(n, f_deep),
			ec2IsSafeGroup_deep(n),
			ecHasOrderA_deep(n, ec_d, ec_deep, n));
}

err_t dstuValParams(const dstu_params* params)
{
	err_t code;
	// состояние
	ec_o* ec;
	void* stack;
	// старт
	code = _dstuCreateEc(&ec, params, _dstuValParams_deep);
	ERR_CALL_CHECK(code);
	stack = objEnd(ec, void);
	// проверить кривую и базовую точку
	if (wwBitSize(ec->order, ec->f->n) <= 160 ||
		!ec2IsValid(ec, stack) ||
		!ec2SeemsValidGroup(ec, stack) ||
		!ec2IsSafeGroup(ec, 32, stack) ||
		!ecHasOrderA(ec->base, ec, ec->order, ec->f->n, stack))
		code = ERR_BAD_PARAMS;
	// завершение
	_dstuCloseEc(ec);
	return code;
}

/*
*******************************************************************************
Управление точками
*******************************************************************************
*/

static size_t _dstuGenPoint_deep(size_t n, size_t f_deep, size_t ec_d, 
	size_t ec_deep)
{
	return O_OF_W(3 * n) + 
		utilMax(2,
			gf2QSolve_deep(n, f_deep),
			ecHasOrderA_deep(n, ec_d, ec_deep, n));
}

err_t dstuGenPoint(octet point[], const dstu_params* params, gen_i rng, 
	void* rng_state)
{
	err_t code;
	// состояние
	ec_o* ec;
	word* x;
	word* y;
	word* t;
	void* stack;
	// проверить rng
	if (rng == 0)
		return ERR_BAD_RNG;
	// старт
	code = _dstuCreateEc(&ec, params, _dstuGenPoint_deep);
	ERR_CALL_CHECK(code);
	// проверить входные указатели
	if (!memIsValid(point, 2 * ec->f->no))
	{
		_dstuCloseEc(ec);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	x = objEnd(ec, word);
	y = x + ec->f->n;
	t = y + ec->f->n;
	stack = t + ec->f->n;
	// пока точка не сгенерирована
	while (1)
	{
		// сгенерировать x-координату
		// [алгоритм из раздела 6.4 ДСТУ --- обрезка x]
		rng(x, ec->f->no, rng_state);
		wwFrom(x, x, ec->f->no);
		wwTrimHi(x, ec->f->n, gf2Deg(ec->f));
		// y <- x^2
		qrSqr(y, x, ec->f, stack);
		// t <- x^3
		qrMul(t, x, y, ec->f, stack);
		// t <- x^3 + a x^2 + b
		if (!qrIsZero(ec->A, ec->f))
			gf2Add2(t, y, ec->f);
		gf2Add2(t, ec->B, ec->f);
		// y <- Solve[y^2 + x y == t], ord(x, y) == order?
		if (gf2QSolve(y, x, t, ec->f, stack) &&
			ecHasOrderA(x, ec, ec->order, ec->f->n, stack))
			break;
	}
	// выгрузить точку
	qrTo(point, x, ec->f, stack);
	qrTo(point + ec->f->no, y, ec->f, stack);
	// завершение
	_dstuCloseEc(ec);
	return ERR_OK;
}

static size_t _dstuValPoint_deep(size_t n, size_t f_deep, size_t ec_d, 
	size_t ec_deep)
{
	return O_OF_W(2 * n) + 
		utilMax(2,
			ec2IsOnA_deep(n, f_deep),
			ecHasOrderA_deep(n, ec_d, ec_deep, n));
}

err_t dstuValPoint(const dstu_params* params, const octet point[])
{
	err_t code;
	// состояние
	ec_o* ec;
	word* x;
	word* y;
	void* stack;
	// старт
	code = _dstuCreateEc(&ec, params, _dstuValPoint_deep);
	ERR_CALL_CHECK(code);
	// проверить входные указатели
	if (!memIsValid(point, 2 * ec->f->no))
	{
		_dstuCloseEc(ec);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	x = objEnd(ec, word);
	y = x + ec->f->n;
	stack = y + ec->f->n;
	// (x, y) лежит на ЭК? (x, y) имеет порядок order?
	if (!qrFrom(x, point, ec->f, stack) ||
		!qrFrom(y, point + ec->f->no, ec->f, stack) ||
		!ec2IsOnA(x, ec, stack) ||
		!ecHasOrderA(x, ec, ec->order, ec->f->n, stack))
		code = ERR_BAD_POINT;
	// завершение
	_dstuCloseEc(ec);
	return code;
}

static size_t _dstuCompressPoint_deep(size_t n, size_t f_deep, size_t ec_d, 
	size_t ec_deep)
{
	return O_OF_W(2 * n) + gf2Tr_deep(n, f_deep);
}

err_t dstuCompressPoint(octet xpoint[], const dstu_params* params, 
	const octet point[])
{
	err_t code;
	// состояние
	ec_o* ec;
	word* x;
	word* y;
	void* stack;
	// старт
	code = _dstuCreateEc(&ec, params, _dstuCompressPoint_deep);
	ERR_CALL_CHECK(code);
	// проверить входные указатели
	if (!memIsValid(point, 2 * ec->f->no) || 
		!memIsValid(xpoint, ec->f->no))
	{
		_dstuCloseEc(ec);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	x = objEnd(ec, word);
	y = x + ec->f->n;
	stack = y + ec->f->n;
	// загрузить точку
	if (!qrFrom(x, point, ec->f, stack) ||
		!qrFrom(y, point + ec->f->no, ec->f, stack))
	{
		_dstuCloseEc(ec);
		return ERR_BAD_POINT;
	}
	// x == 0?
	if (wwIsZero(x, ec->f->n))
	{
		_dstuCloseEc(ec);
		return ERR_OK;
	}
	// y <- y / x
	qrDiv(y, y, x, ec->f, stack);
	// xpoint <- x(point), xpoint_0 <- tr(y)
	memMove(xpoint, point, ec->f->no);
	xpoint[0] &= 0xFE;
	xpoint[0] |= gf2Tr(y, ec->f, stack);
	// завершение
	_dstuCloseEc(ec);
	return ERR_OK;
}

static size_t _dstuRecoverPoint_deep(size_t n, size_t f_deep, size_t ec_d, 
	size_t ec_deep)
{
	return O_OF_W(2 * n) + 
		utilMax(2,
			gf2QSolve_deep(n, f_deep),
			gf2Tr_deep(n, f_deep));
}

err_t dstuRecoverPoint(octet point[], const dstu_params* params, 
	const octet xpoint[])
{
	err_t code;
	register bool_t trace;
	// состояние
	ec_o* ec;
	word* x;
	word* y;
	void* stack;
	// старт
	code = _dstuCreateEc(&ec, params, _dstuRecoverPoint_deep);
	ERR_CALL_CHECK(code);
	// проверить входные указатели
	if (!memIsValid(xpoint, ec->f->no) || 
		!memIsValid(point, 2 * ec->f->no))
	{
		_dstuCloseEc(ec);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	x = objEnd(ec, word);
	y = x + ec->f->n;
	stack = y + ec->f->n;
	// загрузить сжатое представление точки
	if (!qrFrom(x, xpoint, ec->f, stack))
	{
		_dstuCloseEc(ec);
		return ERR_BAD_POINT;
	}
	// x == 0?
	if (qrIsZero(x, ec->f))
	{
		size_t m = gf2Deg(ec->f);
		// b <- b^{2^{m - 1}}
		while (--m)
			qrSqr(ec->B, ec->B, ec->f, stack);
		// выгрузить y-координату
		qrTo(point + ec->f->n, ec->B, ec->f, stack);
		// все нормально
		_dstuCloseEc(ec);
		return ERR_OK;
	}
	// восстановить первый разряд x
	trace = wwTestBit(x, 0);
	wwSetBit(x, 0, 0);
	if (gf2Tr(x, ec->f, stack) != (bool_t)params->A)
		wwSetBit(x, 0, 1);
	// y <- x + a + b / x^2
	qrSqr(y, x, ec->f, stack);
	qrDiv(y, ec->B, y, ec->f, stack);
	gf2Add2(y, x, ec->f);
	if (params->A)
		wwFlipBit(y, 0);
	// Solve[z^2 + z == y]
	if (!gf2QSolve(y, ec->f->unity, y, ec->f, stack))
	{
		trace = 0;
		_dstuCloseEc(ec);
		return ERR_BAD_PARAMS;
	}
	// tr(y) == trace?
	if (gf2Tr(y, ec->f, stack) == trace)
		// y <- y * x
		qrMul(y, x, y, ec->f, stack);
	else
		// y <- (y + 1) * x
		qrMul(y, x, y, ec->f, stack),
		gf2Add2(y, x, ec->f);
	// выгрузить точку
	qrTo(point, x, ec->f, stack);
	qrTo(point + ec->f->no, y, ec->f, stack);
	// все нормально
	trace = 0;
	_dstuCloseEc(ec);
	return code;
}

/*
*******************************************************************************
Управление ключами
*******************************************************************************
*/

static size_t _dstuGenKeypair_deep(size_t n, size_t f_deep, size_t ec_d, 
	size_t ec_deep)
{
	return O_OF_W(3 * n) + 
		ecMulA_deep(n, ec_d, ec_deep, n);
}

err_t dstuGenKeypair(octet privkey[], octet pubkey[], 
	const dstu_params* params, gen_i rng, void* rng_state)
{
	err_t code;
	size_t order_n, order_no, order_nb;
	// состояние
	ec_o* ec;
	word* d;
	word* x;
	word* y;
	void* stack;
	// проверить rng
	if (rng == 0)
		return ERR_BAD_RNG;
	// старт
	code = _dstuCreateEc(&ec, params, _dstuGenKeypair_deep);
	ERR_CALL_CHECK(code);
	// размерности order
	order_nb = wwBitSize(ec->order, ec->f->n);
	order_no = O_OF_B(order_nb);
	order_n = W_OF_B(order_nb);
	// проверить входные указатели
	if (!memIsValid(privkey, order_no) || 
		!memIsValid(pubkey, 2 * ec->f->no))
	{
		_dstuCloseEc(ec);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	d = objEnd(ec, word);
	x = d + ec->f->n;
	y = x + ec->f->n;
	stack = y + ec->f->n;
	// d <-R {1,2,..., order - 1}
	// [алгоритм из раздела 6.3 ДСТУ --- обрезка d]
	wwSetZero(d, order_n);
	while (1)
	{
		rng(d, O_OF_B(order_nb), rng_state);
		wwFrom(d, d, O_OF_B(order_nb));
		wwTrimHi(d, order_n, order_nb - 1);
		ASSERT(wwCmp(d, ec->order, order_n) < 0);
		// 0 < d?
		if (!wwIsZero(d, order_n))
			break;
	}
	// Q <- d G
	if (!ecMulA(x, ec->base, ec, d, order_n, stack))
	{
		// если params корректны, то этого быть не должно
		_dstuCloseEc(ec);
		return ERR_BAD_PARAMS;
	}
	// Q <- -Q
	ec2NegA(x, x, ec);
	// выгрузить ключи
	wwTo(privkey, order_no, d);
	qrTo(pubkey, x, ec->f, stack);
	qrTo(pubkey + ec->f->no, y, ec->f, stack);
	// все нормально
	_dstuCloseEc(ec);
	return code;
}

/*
*******************************************************************************
ЭЦП
*******************************************************************************
*/

static size_t _dstuSign_deep(size_t n, size_t f_deep, size_t ec_d, 
	size_t ec_deep)
{
	return O_OF_W(6 * n) + 
		utilMax(2,
			ecMulA_deep(n, ec_d, ec_deep, n),
			zzMulMod_deep(n));
}

err_t dstuSign(octet sig[], const dstu_params* params, size_t ld, 
	const octet hash[], size_t hash_len, const octet privkey[], 
	gen_i rng, void* rng_state)
{
	err_t code;
	size_t order_n, order_no, order_nb;
	// состояние
	ec_o* ec;
	word* e;		/* эфемерный лк */
	word* h;		/* хэш-значение как элемент поля */
	word* x;		/* х-координата эфемерного ок */
	word* y;		/* y-координата эфемерного ок */
	word* r;		/* первая часть ЭЦП */
	word* s;		/* вторая часть ЭЦП */
	void* stack;
	// проверить rng
	if (rng == 0)
		return ERR_BAD_RNG;
	// старт
	code = _dstuCreateEc(&ec, params, _dstuSign_deep);
	ERR_CALL_CHECK(code);
	// размерности order
	order_nb = wwBitSize(ec->order, ec->f->n);
	order_no = O_OF_B(order_nb);
	order_n = W_OF_B(order_nb);
	// проверить входные указатели
	// шаги 1, 2: проверка params, privkey
	// шаг 3: проверить ld
	if (!memIsValid(privkey, order_no) || 
		ld % 16 != 0 || ld < 16 * order_no ||
		!memIsValid(hash, hash_len) ||
		!memIsValid(sig, O_OF_B(ld)))
	{
		_dstuCloseEc(ec);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	e = objEnd(ec, word);
	h = e + ec->f->n;
	x = h + ec->f->n;
	y = x + ec->f->n;
	r = y + ec->f->n;
	s = r + ec->f->n;
	stack = s + ec->f->n;
	// шаги 4 -- 6: хэширование
	// шаг 7: перевести hash в элемент основного поля h
	// [алгоритм из раздела 5.9 ДСТУ]
	if (hash_len < ec->f->no)
	{
		memCopy(h, hash, hash_len);
		memSetZero((octet*)h + hash_len, ec->f->no - hash_len);
	}
	else
	{
		memCopy(h, hash, ec->f->no);
		// memTrimHi(h, ec->f->no, gf2Deg(ec->f));
		((octet*)h)[ec->f->no - 1] &= (1 << gf2Deg(ec->f) % 8) - 1;
	}
	qrFrom(h, (octet*)h, ec->f, stack);
	// шаг 7: если h == 0, то h <- 1
	if (qrIsZero(h, ec->f))
		qrSetUnity(h, ec->f);
	// шаг 8: e <-R {1,2,..., order - 1}
	// [алгоритм из раздела 6.3 ДСТУ --- обрезка e]
step8:
	while (1)
	{
		rng(e, O_OF_B(order_nb), rng_state);
		wwFrom(e, e, O_OF_B(order_nb));
		wwTrimHi(e, order_n, order_nb - 1);
		ASSERT(wwCmp(e, ec->order, order_n) < 0);
		if (!wwIsZero(e, order_n))
			break;
	}
	// шаг 8: (x, y) <- e G
	if (!ecMulA(x, ec->base, ec, e, order_n, stack))
	{
		// если params корректны, то этого быть не должно
		_dstuCloseEc(ec);
		return ERR_BAD_PARAMS;
	}
	// шаг 8: если x == 0, то повторить генерацию
	if (qrIsZero(x, ec->f))
		goto step8;
	// шаг 9: y <- x * h
	qrMul(y, x, h, ec->f, stack);
	// шаг 10: r <- \bar{y}
	ASSERT(order_n <= ec->f->n);
	qrTo((octet*)r, y, ec->f, stack);
	wwFrom(r, r, order_no);
	wwTrimHi(r, order_n, order_nb - 1);
	// шаг 11: если r = 0, то повторить генерацию
	if (wwIsZero(r, order_n))
		goto step8;
	// шаг 12: s <- (e + dr) mod order
	wwFrom(s, privkey, order_no);
	zzMulMod(s, s, r, ec->order, order_n, stack);
	zzAddMod(s, s, e, ec->order, order_n);
	// шаг 13: если s = 0, то повторить генерацию
	if (wwIsZero(s, order_n))
		goto step8;
	// шаг 14: сформировать ЭЦП из r и s
	// [алгоритм из раздела 5.10 ДСТУ]
	memSetZero(sig, O_OF_B(ld));
	wwTo(sig, order_no, r);
	wwTo(sig + ld / 16, order_no, s);
	// все нормально
	_dstuCloseEc(ec);
	return code;
}

static size_t _dstuVerify_deep(size_t n, size_t f_deep, size_t ec_d, 
	size_t ec_deep)
{
	return O_OF_W(5 * n) + 
		ecAddMulA_deep(n, ec_d, ec_deep, 2, n, n);
}

err_t dstuVerify(const dstu_params* params, size_t ld, const octet hash[], 
	size_t hash_len, const octet sig[], const octet pubkey[])
{
	err_t code;
	size_t order_n, order_no, order_nb, i;
	// состояние
	ec_o* ec;
	word* h;		/* хэш-значение как элемент поля */
	word* x;		/* х-координата эфемерного ок */
	word* y;		/* y-координата эфемерного ок */
	word* r;		/* первая часть ЭЦП */
	word* s;		/* вторая часть ЭЦП */
	void* stack;
	// старт
	code = _dstuCreateEc(&ec, params, _dstuVerify_deep);
	ERR_CALL_CHECK(code);
	// размерности order
	order_nb = wwBitSize(ec->order, ec->f->n);
	order_no = O_OF_B(order_nb);
	order_n = W_OF_B(order_nb);
	// проверить входные указатели
	// шаги 1, 2: обработка идентификатора хэш-функции
	// шаг 3: проверить ld
	if (!memIsValid(pubkey, 2 * ec->f->no) || 
		ld % 16 != 0 || ld < 16 * order_no ||
		!memIsValid(hash, hash_len))
	{
		_dstuCloseEc(ec);
		return ERR_BAD_INPUT;
	}
	// раскладка состояния
	h = objEnd(ec, word);
	x = h + ec->f->n;
	y = x + ec->f->n;
	r = y + ec->f->n;
	s = r + ec->f->n;
	stack = s + ec->f->n;
	// шаг 4: проверить params
	// шаг 5: проверить pubkey
	// [минимальная проверка принадлежности координат базовому полю]
	if (!qrFrom(x, pubkey, ec->f, stack) || 
		!qrFrom(y, pubkey + ec->f->no, ec->f, stack))
	{
		_dstuCloseEc(ec);
		return ERR_BAD_PUBKEY;
	}
	// шаги 6, 7: хэширование
	// шаг 8: перевести hash в элемент основного поля h
	// [алгоритм из раздела 5.9 ДСТУ]
	if (hash_len < ec->f->no)
	{
		memCopy(h, hash, hash_len);
		memSetZero((octet*)h + hash_len, ec->f->no - hash_len);
	}
	else
	{
		memCopy(h, hash, ec->f->no);
		// memTrimHi(h, ec->f->no, gf2Deg(ec->f));
		((octet*)h)[ec->f->no - 1] &= (1 << gf2Deg(ec->f) % 8) - 1;
	}
	qrFrom(h, (octet*)h, ec->f, stack);
	// шаг 8: если h = 0, то h <- 1
	if (qrIsZero(h, ec->f))
		qrSetUnity(h, ec->f);
	// шаг 9: выделить части подписи
	wwFrom(r, sig, order_no);
	wwFrom(s, sig + ld / 16, order_no);
	for (i = order_no; i < ld / 16; ++i)
		if (sig[i] || sig[i + ld / 16])
		{
			_dstuCloseEc(ec);
			return ERR_BAD_SIG;
		}
	// шаги 10, 11: проверить r и s
	if (wwIsZero(r, order_n) ||
		wwIsZero(s, order_n) ||
		wwCmp(r, ec->order, order_n) >= 0 ||
		wwCmp(s, ec->order, order_n) >= 0)
	{
		_dstuCloseEc(ec);
		return ERR_BAD_SIG;
	}
	// шаг 12: R <- sP + rQ
	if (!ecAddMulA(x, ec, stack, 2, ec->base, s, order_n, x, r, order_n))
	{
		_dstuCloseEc(ec);
		return ERR_BAD_SIG;
	}
	// шаг 13: y <- h * x
	qrMul(y, x, h, ec->f, stack);
	// шаг 14: r' <- \bar{y}
	ASSERT(order_n <= ec->f->n);
	qrTo((octet*)s, y, ec->f, stack);
	wwFrom(s, s, order_no);
	wwTrimHi(s, order_n, order_nb - 1);
	// шаг 15:
	if (!wwEq(r, s, order_n))
		code = ERR_BAD_SIG;
	// все нормально
	_dstuCloseEc(ec);
	return code;
}
