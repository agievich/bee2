/*
*******************************************************************************
\file cmd_term.c
\brief Command-line interface to Bee2: terminal
\project bee2/cmd 
\created 2022.06.08
\version 2025.06.09
\copyright The Bee2 authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

#include "bee2/cmd.h"

/*
*******************************************************************************
Терминал

\thanks
https://www.flipcode.com/archives/_kbhit_for_Linux.shtml
(Morgan McGuire [morgan@cs.brown.edu])
https://stackoverflow.com/questions/29335758/using-kbhit-and-getch-on-linux
https://askcodes.net/questions/how-to-implement-getch---function-of-c-in-linux-
*******************************************************************************
*/

#ifdef OS_UNIX

#include <termios.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

bool_t cmdTermKbhit()
{
	struct termios oldattr, newattr;
	int bytesWaiting;
	tcgetattr(STDIN_FILENO, &oldattr);
	newattr = oldattr;
	newattr.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newattr);
	ioctl(STDIN_FILENO, FIONREAD, &bytesWaiting);
	tcsetattr(STDIN_FILENO, TCSANOW, &oldattr);
	return bytesWaiting > 0;
}

int cmdTermGetch()
{
	struct termios oldattr, newattr;
	int ch;
	fflush(stdout);
	tcgetattr(STDIN_FILENO, &oldattr);
	newattr = oldattr;
	newattr.c_lflag &= ~(ICANON | ECHO);
	newattr.c_cc[VMIN] = 1;
	newattr.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSANOW, &newattr);
	ch = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldattr);
	return ch;
}

#elif defined OS_WIN

#include <conio.h>

bool_t cmdTermKbhit()
{
	return _kbhit();
}

int cmdTermGetch()
{
	return _getch();
}

#else

bool_t cmdTermKbhit()
{
	return FALSE;
}

int cmdTermGetch()
{
	char ch;
	scanf(" %c", &ch);
	return ch;
}

#endif
