/*
*******************************************************************************
\file ww-test.c
\brief Tests for arbitrary length words
\project bee2/test
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author (C) Stanislav Poruchnik [PoruchnikStanislav@gmail.com]
\created 2017.05.21
\version 2017.05.21
\license This program is released under the GNU General Public License
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/mem.h>
#include <bee2/core/prng.h>
#include <bee2/core/util.h>
#include <bee2/core/word.h>
#include <bee2/math/zz.h>
#include <bee2/math/ww.h>

/*
*******************************************************************************
Тестирование
*******************************************************************************
*/

size_t checkOddRecordingResult_deep(size_t n) {
	return n;
}

bool_t checkOddRecordingResult(word* odd_recording, size_t m, const word* d, size_t n, size_t k,
	size_t w, void* stack) {
	int i = 0;
	const word hi_bit = WORD_BIT_POS(w);
	word digit;
	word* result = (word*)stack;
	stack = result + n;

	for (i = k - 1; i >= 0; --i) {
		wwShHi(result, n, w);
		digit = wwGetBits(odd_recording, i*(w + 1), w + 1);
		if (digit & hi_bit) {
			zzSubW2(result, n, digit ^ hi_bit);
		}
		else {
			zzAddW2(result, n, digit);
		}
	}
	return wwEq(d, result, n);
}

size_t wwTestOddRecording_deep(size_t n, size_t w) {
	size_t m = W_OF_B(wwOddRecording_size(n, w) * (w + 1));
	return prngCOMBO_keep() + n + m + checkOddRecordingResult_deep(n);
}

bool_t wwTestOddRecording()
{
	octet state[128];
	octet* combo_state;
	word* d;
	word* odd_recording;
	void* stack;
	size_t n = 8;
	size_t w = 5;
	size_t k = wwOddRecording_size(n, w);
	size_t m = W_OF_B(k * (w + 1));

	//раскладка в стек
	combo_state = (octet*)state;
	d = (word*)(combo_state + prngCOMBO_keep());
	odd_recording = d + n;
	stack = odd_recording + m;

	ASSERT(wwTestOddRecording_deep(n, w) <= sizeof(state));

	// создать генератор COMBO
	prngCOMBOStart(combo_state, utilNonce32());
	{
		const size_t reps = 1000;
		size_t i;
		for (i = 0; i < reps; ++i)
		{
			//сгенерировать число и сделать нечетным
			prngCOMBOStepR(d, n, combo_state);
			d[0] |= 1;

			wwSetZero(odd_recording, m);
			wwOddRecording(odd_recording, m, d, n, k, w);

			//проверка результата
			if (!checkOddRecordingResult(odd_recording, m, d, n, k, w, stack)) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

bool_t wwTest()
{
	return wwTestOddRecording();
}
