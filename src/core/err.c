/*
*******************************************************************************
\file err.c
\brief Errors
\project bee2 [cryptographic library]
\created 2012.07.09
\version 2022.10.31
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#include "bee2/core/err.h"
#include "bee2/core/util.h"

/*
*******************************************************************************
Сообщение об ошибке
*******************************************************************************
*/

typedef struct {
	err_t code;
	const char* msg;
} err_msg;

static const err_msg _messages[] = {
	{ERR_OK, "Success"},
	// system
	{ERR_SYS, "Unknown system error"},
	{ERR_BAD_UNIT, "Invalid device"},
	{ERR_BAD_FILE, "Invalid file"},
	{ERR_BAD_TIMER, "Invalid timer"},
	{ERR_BAD_FUNCTION, "Invalid function"},
	{ERR_BAD_COMMAND, "Invalid command"},
	{ERR_BAD_LENGTH, "Invalid length"},
	{ERR_BAD_INPUT, "Invalid input data"},
	{ERR_OUTOFMEMORY, "Out of memory"},
	{ERR_ACCESS_DENIED, "Access denied"},
	{ERR_NOT_READY, "Device is not ready"},
	{ERR_BUSY, "Device is busy"},
	{ERR_TIMEOUT, "Timeout"},
	{ERR_NOT_IMPLEMENTED, "Function is not implemented"},
	{ERR_AFTER, "Aftereffect of prevoius errors"},
	// file
	{ERR_FILE_CREATE, "Unable to create the file"},
	{ERR_FILE_NOT_FOUND, "Unable to find the file"},
	{ERR_FILE_OPEN, "Unable to open the file"},
	{ERR_FILE_EXISTS, "The file exists"},
	{ERR_FILE_TOO_MANY_OPEN, "Too many open files"},
	{ERR_FILE_WRITE, "Cannot write to the file"},
	{ERR_FILE_READ, "Cannot read from the file"},
	{ERR_FILE_EOF, "Reached the end of the file"},
	// core
	{ERR_BAD_OID, "Incorrect object identifier"},
	{ERR_BAD_ENTROPY, "Error while collecting entropy"},
	{ERR_NOT_ENOUGH_ENTROPY, "Not enough entropy"},
	{ERR_BAD_RNG, "Incorrect random number generator"},
	{ERR_BAD_ANG, "Incorrect any number generator"},
	{ERR_BAD_FORMAT, "Invalid format"},
	{ERR_BAD_TIME, "Invalid time"},
	{ERR_BAD_DATE, "Invalid date"},
	{ERR_BAD_NAME, "Invalid name"},
	{ERR_OUTOFRANGE, "Out of range"},
	{ERR_BAD_ACL, "Invalid access control list"},
	{ERR_BAD_APDU, "Incorrect APDU command or response"},
	// math
	{ERR_BAD_POINT, "Invalid elliptic curve point"},
	{ERR_NOT_PRIME, "The number is not prime"},
	{ERR_NOT_COPRIME, "The items are not coprime"},
	{ERR_NOT_IRRED, "The polynomial is not irreducible"},
	// crypto
	{ERR_BAD_PARAMS, "Invalid domain parameters"},
	{ERR_BAD_SECKEY, "Invalid secret key"},
	{ERR_BAD_PRIVKEY, "Invalid private key"},
	{ERR_BAD_PUBKEY, "Invalid public key"},
	{ERR_BAD_KEYPAIR, "Invalid private/public keypair"},
	{ERR_BAD_CERT, "Incorrect public key certificate"},
	{ERR_BAD_SHAREDKEY, "Incorrect shared key"},
	{ERR_BAD_SHAREKEY, "Incorrect secret share"},
	{ERR_BAD_HASH, "Incorrect hash"},
	{ERR_BAD_SIG, "Incorrect signature"},
	{ERR_BAD_MAC, "Incorrect authentication tag"},
	{ERR_BAD_KEYTOKEN, "Invalid key token"},
	{ERR_BAD_LOGIC, "Incorrect (protocol) logic"},
	{ERR_BAD_PWD, "Incorrect password"},
	{ERR_KEY_NOT_FOUND, "Unable to find the key"},
	{ERR_NO_TRUST, "No trust"},
	{ERR_AUTH, "Authentication failed"},
	{ERR_SELFTEST, "Self-tests failed"},
	{ERR_STATTEST, "Statistical tests failed"},
	// cmd
	{ERR_CMD_NOT_FOUND, "Command not found"},
	{ERR_CMD_EXISTS, "Command is already registered"},
	{ERR_CMD_PARAMS, "Invalid command parameters"},
	{ERR_CMD_DUPLICATE, "Duplicate command parameters"},
};

const char* errMsg(err_t code)
{
	size_t i;
	for (i = 0; i < COUNT_OF(_messages); ++i)
		if (_messages[i].code == code)
			return _messages[i].msg;
	return 0;
}
