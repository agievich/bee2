/*
*******************************************************************************
\file err.c
\brief Errors
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.07.09
\version 2014.04.22
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Сообщение об ошибке

\todo Перебросить в header.
*******************************************************************************
*/

/*!	brief Сообщение об ошибке

	Формируется строка, которая содержит сообщение об ошибке с кодом code.
	\return Строка с сообщением об ошибке, или 0, если ошибка нераспознана.
*/
const char* errMsg(
	err_t code			/*!< [in] код ошибки */
);

/*
*******************************************************************************
Сообщение об ошибке

\todo Разобрать коды всех ошибок.
*******************************************************************************
*/

typedef struct {
	err_t code;
	const char* msg;
} err_msg;

static const err_msg _messages[] = {
	{ERR_OK, "Success"},
	{ERR_BAD_UNIT, "Bad unit"},
};

const char* errMsg(err_t code)
{
	size_t i;

	for (i = 0; i < COUNT_OF(_messages); ++i)
		if (_messages[i].code == code)
			return _messages[i].msg;
	return 0;
}

