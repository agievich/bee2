@echo off
rem ===========================================================================
rem \brief Testing command-line interface
rem \project bee2evp/cmd
rem \created 2022.06.24
rem \version 2023.06.19
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
rem  bee2cmd/bsum
rem ===========================================================================

echo ****** Testing bee2cmd/bsum...

del /q check32 check256 2> nul

bee2cmd bsum -bash31 bee2cmd.exe
if %ERRORLEVEL% equ 0 goto Error

bee2cmd bsum -bash32 bee2cmd.exe test.cmd > check32
if %ERRORLEVEL% neq 0 goto Error

bee2cmd bsum -bash32 -c check32
if %ERRORLEVEL% neq 0 goto Error

bee2cmd bsum bee2cmd.exe test.cmd > check256
if %ERRORLEVEL% neq 0 goto Error

bee2cmd bsum -belt-hash -c check256
if %ERRORLEVEL% neq 0 goto Error

bee2cmd bsum -c check32
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

bee2cmd pwd gen share:"-l128 -t3 -crc -pass pass:zed s1 s2 s3 s4 s5"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd gen share:"-l256 -t3 -crc -pass pass:zed s1 s2 s3 s4 s5"
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

bee2cmd pwd val share:"-l256 -crc -pass pass:zed s1 s2 s3"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd val share:"-pass pass:zed s2 s3 s4 s5"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd val share:"-pass pass:zed -crc s2 s3 s4 s5"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd print share:"-l128 -pass pass:zed s5 s1 s3"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd print share:"-l256 -pass pass:zed s2 s1 s5 s3"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd print share:"-pass pass:zed s1 s2 s3 s4 s5"
if %ERRORLEVEL% neq 0 goto Error

del /q ss1 ss2 ss3 2> nul

bee2cmd pwd gen share:"-l192 -pass share:\"-pass pass:zed s1 s2 s3\" ss1 ss2 ss3"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd val share:"-pass share:\"-pass pass:zed s1 s2 s2\" ss1 ss2"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd val share:"-pass share:\"-pass pass:zed s1 s2 s3\" ss1 ss1"
if %ERRORLEVEL% equ 0 goto Error

bee2cmd pwd val share:"-pass share:\"-pass pass:zed s1 s2 s3\" ss2 ss3"
if %ERRORLEVEL% neq 0 goto Error

bee2cmd pwd val share:"-pass -crc share:\"-pass pass:zed s1 s2 s3\" ss2 ss3"
if %ERRORLEVEL% equ 0 goto Error

echo ****** OK

rem ===========================================================================
rem  bee2cmd/kg
rem ===========================================================================

echo ****** Testing bee2cmd/kg...

del /q privkey0 privkey1 privkey2 privkey3 pubkey0 pubkey2 pubkey3 2> nul

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

bee2cmd kg extr -pass pass:alice privkey2 pubkey2
if %ERRORLEVEL% neq 0 goto Error

for %%A in (pubkey2) do set pubkey2_len=%%~zA
if %pubkey2_len% neq 64 goto Error

bee2cmd kg gen -l96 -pass pass:bob privkey3
if %ERRORLEVEL% neq 0 goto Error

bee2cmd kg extr -pass pass:bob privkey3 pubkey3
if %ERRORLEVEL% neq 0 goto Error

echo ****** OK

rem ===========================================================================
rem  bee2cmd/cvc
rem ===========================================================================

echo ****** Testing bee2cmd/cvc...

del /q cert0 req1 cert1 pubkey1 req2 req21 cert2 req3 cert3 2> nul

bee2cmd cvc root -authority BYCA0000 -from 220707 -until 990707 ^
  -pass pass:root -eid EEEEEEEEEE -esign 7777 privkey0 cert0
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc print cert0
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc req -authority BYCA0000 -holder BYCA1000 -from 220711 ^
  -until 221231 -pass pass:trent -eid FFFFFFFFFF -esign 7777 privkey1 req1
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc print req1
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc iss -authority BYCA0000 -pass pass:root privkey0 cert0 req1 cert1
if %ERRORLEVEL% equ 0 goto Error

bee2cmd cvc iss -from 220712 -until 221130 -holder BYCA1023 ^
  -eid DDDDDDDDDD -esign BBBB -pass pass:root privkey0 cert0 req1 cert1
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc print cert1
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc extr cert1 pubkey1
if %ERRORLEVEL% neq 0 goto Error

for %%A in (pubkey1) do set pubkey1_len=%%~zA
if %pubkey1_len% neq 96 goto Error

bee2cmd cvc req -authority BYCA1023 -holder "590082394654" -from 220712 ^
  -until 391231 -pass pass:alice -eid 8888888888 -esign 1111 privkey2 req2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc req -authority BYCA1023 -holder "590082394654" -from 000000 ^
  -until 000000 -pass pass:alice privkey2 req21
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc iss -pass pass:trent privkey1 cert1 req2 cert2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc match -pass pass:alice privkey2 cert2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc match -pass pass:alisa privkey2 cert2
if %ERRORLEVEL% equ 0 goto Error

bee2cmd cvc print cert2
if %ERRORLEVEL% neq 0 goto Error

for /f "tokens=* USEBACKQ" %%F in (`bee2cmd cvc print -from cert1`) do (
  set from=%%F
)
if "%from%" neq "220712" goto Error

for /f "tokens=* USEBACKQ" %%F in (`bee2cmd cvc print -until cert1`) do (
  set until=%%F
)
if "%until%" neq "221130" goto Error

for /f "tokens=* USEBACKQ" %%F in (`bee2cmd cvc print -eid cert1`) do (
  set eid=%%F
)
if "%eid%" neq "DDDDDDDDDD" goto Error

for /f "tokens=* USEBACKQ" %%F in (`bee2cmd cvc print -esign cert1`) do (
  set esign=%%F
)
if "%esign%" neq "3333" goto Error

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

bee2cmd cvc val -date cert0 cert1 cert2
if %ERRORLEVEL% equ 0 goto Error

bee2cmd cvc val cert0 cert1 cert2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc shorten -pass pass:trent -until 391230 privkey1 cert1 cert2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc val cert0 cert1 cert2
if %ERRORLEVEL% neq 0 goto Error

for /f "tokens=* USEBACKQ" %%F in (`bee2cmd cvc print -until cert2`) do (
  set until=%%F
)
if "%until%" neq "391230" goto Error

bee2cmd cvc req -authority BYCA1023 -from 221030 -until 391231 ^
  -holder 590082394655 -pass pass:bob privkey3 req3
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc print req3
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvc iss -pass pass:trent privkey1 cert1 req3 cert3
if %ERRORLEVEL% neq 0 goto Error

echo ****** OK

rem ===========================================================================
rem  bee2cmd/sig
rem ===========================================================================

echo ****** Testing bee2cmd/sig...

del /q ff ss cert01 cert11 cert21 body sig 2> nul

echo test> ff
echo sig> ss

bee2cmd sig val -pubkey pubkey2 ff ss
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig val -anchor cert0 ff ss
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig val -anchor cert2 ff ss
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig val -pubkey pubkey2 ff ss
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig val -anchor cert0 ff ff
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig val -anchor cert2 ff ff
if %ERRORLEVEL% equ 0 goto Error

del /q ss 1> nul

bee2cmd sig sign -certs "cert1 cert2" -date 400101 -pass pass:alice ^
  privkey2 ff ss
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig sign -certs "cert1 cert2" -date 230526 -pass pass:alice ^
  privkey2 ff ss
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -pubkey pubkey2 ff ss
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert2 ff ss
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert1 ff ss
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert0 ff ss
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig sign -certs "cert0 cert1 cert2" -pass pass:alice privkey2 ff ff
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -pubkey pubkey2 ff ff
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert2 ff ff
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert1 ff ff
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert0 ff ff
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig extr -cert0 ff cert01
if %ERRORLEVEL% neq 0 goto Error

fc /b cert01 cert0 1> nul
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig extr -cert1 ff cert11
if %ERRORLEVEL% neq 0 goto Error

fc /b cert1 cert11 1> nul
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig extr -cert2 ff cert21
if %ERRORLEVEL% neq 0 goto Error

fc /b cert2 cert21 1> nul
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig extr -body ff body
if %ERRORLEVEL% neq 0 goto Error

for /f "tokens=* USEBACKQ" %%F in (`type body`) do (
  set body=%%F
)
if "%body%" neq "test" goto Error

bee2cmd sig extr -sig ff sig
if %ERRORLEVEL% neq 0 goto Error

del /q ss body 2> nul

bee2cmd sig sign -certs cert2 -pass pass:alice privkey2 ff ss
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -pubkey pubkey2 ff ss
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert2 ff ss
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert1 ff ss
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig extr -body ss body
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig sign -pass pass:alice -date 230526 privkey2 ff ff
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -pubkey pubkey2 ff ff
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert2 ff ff
if %ERRORLEVEL% equ 0 goto Error

bee2cmd sig print ss
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig print ff
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig print -date ss
if %ERRORLEVEL% equ 0 goto Error

for /f "tokens=* USEBACKQ" %%F in (`bee2cmd sig print -certc ss`) do (
  set certc=%%F
)
if "%certc%" neq "1" goto Error

bee2cmd sig sign -pass pass:bob -certs "cert1 cert3" privkey3 ff ff
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -pubkey pubkey3 ff ff
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert1 ff ff
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert3 ff ff
if %ERRORLEVEL% neq 0 goto Error

echo ****** OK

rem ===========================================================================
rem  bee2cmd/cvr
rem ===========================================================================

echo ****** Testing bee2cmd/cvr...

del /q ring2 cert21 cert31 2> nul

bee2cmd cvr init -pass pass:alice privkey2 cert2 ring2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvr add -pass pass:alice privkey2 cert2 cert3 ring2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvr add -pass pass:alice privkey2 cert2 cert3 ring2
if %ERRORLEVEL% equ 0 goto Error

bee2cmd cvr val cert2 ring2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig val -anchor cert2 ring2 ring2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig find ring2 cert3
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig find ring2 cert2
if %ERRORLEVEL% equ 0 goto Error

bee2cmd cvr extr -cert0 ring2 cert31
if %ERRORLEVEL% neq 0 goto Error

fc /b cert31 cert3 1> nul
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig extr -cert0 ring2 cert21
if %ERRORLEVEL% neq 0 goto Error

fc /b cert21 cert2 1> nul
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvr print ring2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvr print -certc ring2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd sig print ring2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvr add -pass pass:alice privkey2 cert2 cert0 ring2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvr add -pass pass:alice privkey2 cert2 cert1 ring2
if %ERRORLEVEL% neq 0 goto Error

for /f "tokens=* USEBACKQ" %%F in (`bee2cmd cvr print -certc ring2`) do (
  set certc=%%F
)
if "%certc%" neq "3" goto Error

bee2cmd cvr del -pass pass:alice privkey2 cert2 cert1 ring2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvr del -pass pass:alice privkey2 cert2 cert0 ring2
if %ERRORLEVEL% neq 0 goto Error

bee2cmd cvr del -pass pass:alice privkey2 cert2 cert0 ring2
if %ERRORLEVEL% equ 0 goto Error

echo ****** OK

rem ===========================================================================
rem  bee2cmd/es
rem ===========================================================================

del /q dd 2> nul

bee2cmd es print
if %ERRORLEVEL% neq 0 goto Error

bee2cmd es read sys 1 dd
if %ERRORLEVEL% neq 0 goto Error

for %%A in (dd) do set dd_len=%%~zA
if %dd_len% neq 1024 goto Error

echo ****** OK

rem ===========================================================================
rem  exit
rem ===========================================================================

goto End

if %ERRORLEVEL% equ 0 goto Error

:Error
echo ****** Failed

:End
