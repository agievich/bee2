@echo off
rem ===========================================================================
rem \brief Testing command-line interface
rem \project bee2evp/cmd
rem \created 2022.06.24
rem \version 2018.07.18
rem ===========================================================================

rem ===========================================================================
rem  bee2cmd/ver
rem ===========================================================================

echo ****** Testing bee2cmd/ver...

bee2cmd ver
if %ERRORLEVEL% neq 0 goto Error

bee2cmd ver ver
if %ERRORLEVEL% equ 0 goto Error

echo ****** OK

rem ===========================================================================
rem  bee2cmd/pwd
rem ===========================================================================

echo ****** Testing bee2cmd/pwd...

del /q s1 s2 s3 s4 s5 2> nul

bee2cmd pwd gen pass:zed
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd gen pass:"zed"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd gen share:"-t2 -t3 -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd gen share:"-t3 -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd gen share:"-l -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd gen share:"-l12 -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd gen share:"-l128 -l -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd gen share:"-l128 -l256 -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd gen share:"-l256 -t3 -pass pass:zed s1 s2 s3 s4 s5"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd val share:"-t3 -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd val share:"-l -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd val share:"-l12 -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd val share:"-l128 -l -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd val share:"-l128 -l256 -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd val share:"-l128 -pass pass:zed s1 s2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd val share:"-l256 -pass pass:zed s1 s2 s3"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd val share:"-pass pass:zed s2 s3 s4 s5"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd print share:"-l128 -pass pass:zed s5 s1 s3"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd print share:"-l256 -pass pass:zed s2 s1 s5 s3"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd print share:"-pass pass:zed s1 s2 s3 s4 s5"
if %ERRORLEVEL% neq 0 goto Error

del /q ss1 ss2 ss3

bee2cmd pwd gen share:"-l192 -pass share:\"-pass pass:zed s1 s2 s3\" ss1 ss2 ss3"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd val share:"-pass share:\"-pass pass:zed s1 s2 s2\" ss1 ss2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd val share:"-pass share:\"-pass pass:zed s1 s2 s3\" ss1 ss1"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd val share:"-pass share:\"-pass pass:zed s1 s2 s3\" ss2 ss3"
if %ERRORLEVEL% neq 0 goto Error

echo ****** OK

rem ===========================================================================
rem  bee2cmd/kg
rem ===========================================================================

echo ****** Testing bee2cmd/kg...

del /q privkey0 privkey1 privkey2 pubkey1 2> nul

bee2cmd kg gen -l256 -pass share:"-pass pass:zed s2 s3 s4"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd kg gen -l256 -pass share:"-pass pass:zed s2 s3 s4" -pass pass:zed
if %ERRORLEVEL% equ 0 goto Error

bee2cmd kg gen -l256 -l192 -pass share:"-pass pass:zed s2 s3 s4" privkey0
if %ERRORLEVEL% equ 0 goto Error

bee2cmd kg gen -l256 -pass share:"-pass pass:zed s2 s3 s4" privkey0
if %ERRORLEVEL% neq 0 goto Error

bee2cmd kg val -pass share:"-pass pass:zed s1 s2 s4" privkey0
if %ERRORLEVEL% neq 0 goto Error

bee2cmd kg chp -passin share:"-pass pass:zed s3 s1 s4" -passout pass:"root" privkey0
if %ERRORLEVEL% neq 0 goto Error

bee2cmd kg gen -pass pass:trent -l192 privkey1
if %ERRORLEVEL% neq 0 goto Error

bee2cmd kg print -pass pass:trent privkey1 > pubkey1
if %ERRORLEVEL% neq 0 goto Error

for /f "tokens=1" %%A in (pubkey1) do @echo|set /p="%%A" > pubkey1
for %%A in (pubkey1) do set pubkey1_len=%%~zA
if %pubkey1_len% neq 192 goto Error

bee2cmd kg gen -pass pass:alice privkey2
if %ERRORLEVEL% neq 0 goto Error

echo ****** OK

rem ===========================================================================
rem  bee2cmd/cvc
rem ===========================================================================

echo ****** Testing bee2cmd/cvc...

del /q cert0 cert1 cert2 req1 req2 2> nul

bee2cmd cvc root -authority BYCA0000 -from 220707 -until 990707 ^
-pass pass:root -eid EEEEEEEEEE -esign 7777 privkey0 cert0
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc print cert0
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc req -authority BYCA0000 -holder BYCA1000 -from 220712 ^
-until 221130 -pass pass:trent -eid DDDDDDDDDD -esign 3333 privkey1 req1
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc print req1
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc iss -pass pass:root privkey0 cert0 req1 cert1
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc print cert1
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc req -authority BYCA1000 -holder "590082394654" -from 220712 ^
-until 391231 -pass pass:alice -eid 8888888888 -esign 1111 privkey2 req2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc iss -pass pass:trent privkey1 cert1 req2 cert2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc match -pass pass:alice privkey2 cert2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc match -pass pass:alisa privkey2 cert2
if %ERRORLEVEL% equ 0 goto Error

bee2cmd cvc print cert2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc val cert0 cert0
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc val -date 220707 cert0 cert1 
if %ERRORLEVEL% equ 0 goto Error

bee2cmd cvc val -date 220712 cert0 cert1 
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc val -date 220707 cert0 cert1 cert2
if %ERRORLEVEL% equ 0 goto Error

bee2cmd cvc val -date 220712 cert0 cert1 cert2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc val -date 220712 cert0 cert1 cert2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc val -date 221201 cert0 cert1 cert2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc val -date 400101 cert0 cert1 cert2
if %ERRORLEVEL% equ 0 goto Error

echo ****** OK

rem ===========================================================================
rem  bee2cmd/sig
rem ===========================================================================

echo ****** Testing bee2cmd/sig...

del /q sig_file test_file 2> nul

bee2cmd kg print -pass pass:alice privkey2 > pubkey2
if %ERRORLEVEL% neq 0 goto Error

for /f "tokens=1" %%A in (pubkey2) do @echo|set /p="%%A" > pubkey2
for %%A in (pubkey2) do set pubkey2_len=%%~zA
if %pubkey2_len% neq 128 goto Error

echo test > test_file
echo sig > sig_file

bee2cmd sig vfy -pubkey pubkey2 test_file sig_file
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig vfy -anchor cert0 test_file sig_file
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig vfy -anchor cert2 test_file sig_file
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig vfy -pubkey pubkey2 test_file test_file
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig vfy -anchor cert0 test_file test_file
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig vfy -anchor cert2 test_file test_file
if %ERRORLEVEL% equ 0 goto Error

del /q sig_file 1> nul

bee2cmd sig sign -cert cert1,cert2 -pass pass:alice privkey2 test_file sig_file
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig vfy test_file sig_file

bee2cmd sig vfy -pubkey pubkey2 test_file sig_file
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig vfy -anchor cert0 test_file sig_file
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig vfy -anchor cert1 test_file sig_file
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig vfy -anchor cert2 test_file sig_file
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig sign -cert cert1,cert2 -pass pass:alice privkey2 test_file test_file
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig vfy test_file sig_file

bee2cmd sig vfy -pubkey pubkey2 test_file test_file
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig vfy -anchor cert0 test_file test_file
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig vfy -anchor cert1 test_file test_file
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig vfy -anchor cert2 test_file test_file
if %ERRORLEVEL% equ 0 goto Error

del sig_file> nul

bee2cmd sig sign -cert cert2 -pass pass:alice privkey2 test_file sig_file
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig vfy -pubkey pubkey2 test_file sig_file
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig vfy -anchor cert1 test_file sig_file
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig vfy -anchor cert2 test_file sig_file
if %ERRORLEVEL% neq 0 goto Error

echo ****** OK

rem ===========================================================================
rem  bee2cmd/sig
rem ===========================================================================

echo ****** Testing bee2cmd/aead...

del /q test_file_decoded test_file_encoded 2> nul

bee2cmd kg print -pass pass:root privkey0 > pubkey0

rem pke test

bee2cmd aead enc -kld PKE -cert cert0 -pubkey pubkey0 test_file test_file_encoded
if %ERRORLEVEL% neq 0 goto Error

bee2cmd aead dec -kld PKE -pass pass:root -privkey privkey0 test_file_encoded test_file_decoded
if %ERRORLEVEL% neq 0 goto Error

fc test_file test_file_decoded
if %ERRORLEVEL% neq 0 goto Error

del /q test_file_decoded 2> nul

bee2cmd aead dec -kld PKE -pass pass:alice -privkey privkey2 test_file_encoded test_file_decoded
if %ERRORLEVEL% equ 0 goto Error

bee2cmd aead val -kld PKE -cert cert0 -pass pass:root -privkey privkey0 test_file_encoded
if %ERRORLEVEL% neq 0 goto Error

bee2cmd aead val -kld PKE -pass pass:root -privkey privkey0 test_file_encoded
if %ERRORLEVEL% neq 0 goto Error

bee2cmd aead val -kld PKE -cert cert0 test_file_encoded
if %ERRORLEVEL% equ 0 goto Error

bee2cmd aead val -kld PKE test_file_encoded
if %ERRORLEVEL% equ 0 goto Error

bee2cmd aead val -kld PKE -cert cert1 test_file_encoded
if %ERRORLEVEL% equ 0 goto Error

bee2cmd aead val -kld PKE -pass pass:alice -privkey privkey2 test_file_encoded
if %ERRORLEVEL% equ 0 goto Error

del /q test_file_decoded test_file_encoded 2> nul

rem with itag

bee2cmd aead enc -kld PKE -cert cert0 -pubkey pubkey0 --itag128 test_file test_file_encoded
if %ERRORLEVEL% neq 0 goto Error

bee2cmd aead dec -kld PKE -pass pass:root -privkey privkey0 test_file_encoded test_file_decoded
if %ERRORLEVEL% neq 0 goto Error

fc test_file test_file_decoded
if %ERRORLEVEL% neq 0 goto Error

rem with itag and adata

del /q test_file_decoded test_file_encoded 2> nul

bee2cmd aead enc -kld PKE -cert cert0 -pubkey pubkey0 --itag128 -adata cert0 test_file test_file_encoded
if %ERRORLEVEL% neq 0 goto Error

bee2cmd aead dec -kld PKE -pass pass:root -privkey privkey0 -adata cert0 test_file_encoded test_file_decoded
if %ERRORLEVEL% neq 0 goto Error

fc test_file test_file_decoded
if %ERRORLEVEL% neq 0 goto Error

del /q test_file_decoded test_file_encoded 2> nul

rem PWD test

bee2cmd aead enc -kld PWD -pass pass:root test_file test_file_encoded
if %ERRORLEVEL% neq 0 goto Error

bee2cmd aead val -kld PWD -pass pass:root  test_file_encoded
if %ERRORLEVEL% neq 0 goto Error

bee2cmd aead val -kld PWD -pass pass:wrongpass  test_file_encoded
if %ERRORLEVEL% equ 0 goto Error

bee2cmd aead dec -kld PWD -pass pass:wrongpass test_file_encoded test_file_decoded
if %ERRORLEVEL% equ 0 goto Error

bee2cmd aead dec -kld PWD -pass pass:root test_file_encoded test_file_decoded
if %ERRORLEVEL% neq 0 goto Error

fc test_file test_file_decoded
if %ERRORLEVEL% neq 0 goto Error

del /q test_file_decoded test_file_encoded 2> nul

rem with itag

bee2cmd aead enc -kld PWD -pass pass:root --itag128 test_file test_file_encoded
if %ERRORLEVEL% neq 0 goto Error

bee2cmd aead dec -kld PWD -pass pass:root test_file_encoded test_file_decoded
if %ERRORLEVEL% neq 0 goto Error

fc test_file test_file_decoded
if %ERRORLEVEL% neq 0 goto Error

rem with itag and adata

del /q test_file_decoded test_file_encoded 2> nul

bee2cmd aead enc -kld PWD -pass pass:root --itag128 -adata cert0 test_file test_file_encoded
if %ERRORLEVEL% neq 0 goto Error

bee2cmd aead dec -kld PWD -pass pass:root -adata cert0 test_file_encoded test_file_decoded
if %ERRORLEVEL% neq 0 goto Error

fc test_file test_file_decoded
if %ERRORLEVEL% neq 0 goto Error


echo ****** OK

rem ===========================================================================
rem  exit
rem ===========================================================================

goto End

if %ERRORLEVEL% equ 0 goto Error

:Error
echo ****** Failed

:End
