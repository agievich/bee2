/*
*******************************************************************************
\file cmd.c
\brief Command-line interface to Bee2
\project bee2/cmd
\created 2022.06.07
\version 2022.06.07
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include <bee2/core/err.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include <stdio.h>

/*
*******************************************************************************
Команды
*******************************************************************************
*/

extern int bsumMain(int, char*[]);

typedef struct {
	const char* name;
	int(*main)(int, char*[]);
} cmd;

static const cmd _cmds[] = {
	{"bsum", bsumMain},
};

/*
*******************************************************************************
Справка
*******************************************************************************
*/

int cmdUsage()
{
	size_t pos;
	printf(
		"bee2cmd: Command-line interface to Bee2 [v%s]\n"
		"Usage:\n" 
		"  bee2cmd {",
		utilVersion());
	for (pos = 0; pos + 1 < COUNT_OF(_cmds); ++pos)
		printf("%s|", _cmds[pos].name);
	printf("%s} ...\n", _cmds[pos].name);
	return -1;
}


/*
*******************************************************************************
main
*******************************************************************************
*/

int main(int argc, char* argv[])
{
	size_t pos;
	if (argc < 2)
		return cmdUsage();
	for (pos = 0; pos < COUNT_OF(_cmds); ++pos)
		if (strEq(argv[1], _cmds[pos].name))
			return _cmds[pos].main(argc - 1,  argv + 1);
	printf("bee2cmd: %s\n", errMsg(ERR_CMD_NOT_FOUND));
	return -1;
}
