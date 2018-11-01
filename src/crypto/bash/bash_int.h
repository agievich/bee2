/*
*******************************************************************************
\file bash_int.h
\brief STB 34.101.77 (bash): internal definitions
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2018.10.30
\version 2018.10.30
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#ifndef __BASH_INT_H
#define __BASH_INT_H

#include "bee2/core/word.h"
#include "bee2/core/u64.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
*******************************************************************************
Вспомогательные функции
*******************************************************************************
*/

void bashF0(u64 s[24]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BASH_INT_H */
