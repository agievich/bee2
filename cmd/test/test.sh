#!/bin/bash
# =============================================================================
# \brief Testing command-line interface
# \project bee2evp/cmd
# \created 2022.06.24
# \version 2024.06.14
# \pre The working directory contains zed.csr.
# =============================================================================

bee2cmd="${BEE2CMD:-./bee2cmd}"
if [ ! -f "${bee2cmd}" ]; then
  bee2cmd=$(command -v bee2cmd)
  if [ ! -f "${bee2cmd}" ]; then
    echo "Set path to bee2cmd executable file to BEE2CMD environment \
      variable or run this script from containing folder."
    exit 1
  fi
fi
this=$(realpath $BASH_SOURCE)

function pause() {
 read -s -n 1 -p "Press any key to continue..."
 echo ""
}

test_ver() {
  $bee2cmd ver \
    || return 1
  $bee2cmd ver ver \
    && return 1
  return 0
}

test_bsum() {
  rm -rf -- check32 check256 -c \
    || return 2
  $bee2cmd bsum -bash31 $bee2cmd \
    && return 1
  $bee2cmd bsum -bash32 $bee2cmd $this > check32 \
    || return 1
  $bee2cmd bsum -bash32 -c check32 \
    || return 1
  $bee2cmd bsum $bee2cmd $this > check256 \
    || return 1
  $bee2cmd bsum -belt-hash -c check256 \
    || return 1
  $bee2cmd bsum -c check32 \
    && return 1
  $bee2cmd bsum -bash-prg-hash2561 $bee2cmd $this > -c \
    || return 1
  $bee2cmd bsum -bash-prg-hash2561 -c \
    && return 1
  $bee2cmd bsum -bash-prg-hash2561 -- -c \
    || return 1
  $bee2cmd bsum -bash-prg-hash2561 -c -- -c \
    || return 1
  $bee2cmd bsum -bash-prg-hash2562 -c -- -c \
    && return 1
  $bee2cmd bsum -c -bash-prg-hash2561 -- -c \
    || return 1
  $bee2cmd bsum -c -bash-prg-hash2561 -c -- -c \
    && return 1
  $bee2cmd bsum -c -belt-hash -bash-prg-hash2561 -- -c \
    && return 1
  $bee2cmd bsum -b -c -- -c \
    && return 1
  return 0
}

test_pwd() {
  rm -rf s1 s2 s3 s4 s5 ss1 ss2 ss3 \
    || return 2
  # pass
  $bee2cmd pwd gen pass:zed \
    && return 1
  $bee2cmd pwd val pass:zed \
    || return 1
  $bee2cmd pwd val pass:"zed" \
    || return 1
  if [ $($bee2cmd pwd print pass:zed) != "zed" ]; then
    return 1
  fi
  # env
  $bee2cmd pwd gen env:BEE2_CMD_TEST \
    && return 1
  unset BEE2_CMD_TEST \
    || return 2
  $bee2cmd pwd val env:BEE2_CMD_TEST \
    && return 1
  export BEE2_CMD_TEST=zed \
    || return 2
  $bee2cmd pwd val env:BEE2_CMD_TEST \
    || return 1
  if [ $($bee2cmd pwd print env:BEE2_CMD_TEST) != "zed" ]; then
    return 1
  fi
  # share
  $bee2cmd pwd gen share:"-t2 -t3 -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd gen share:"-t3 -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd gen share:"-l -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd gen share:"-l12 -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd gen share:"-l128 -l -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd gen share:"-l128 -l256 -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd gen share:"-l128 -crc -t3 -pass pass:zed s1 s2 s3 s4 s5" \
    && return 1
  $bee2cmd pwd gen share:"-l256 -crc -t3 -pass pass:zed s1 s2 s3 s4 s5" \
    || return 1
  $bee2cmd pwd val share:"-t3 -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd val share:"-l -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd val share:"-l12 -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd val share:"-l128 -l -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd val share:"-l128 -l256 -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd val share:"-l128 -pass pass:zed s1 s2" \
    && return 1
  $bee2cmd pwd val share:"-l256 -pass pass:zed s1 s2 s3" \
    || return 1
  $bee2cmd pwd val share:"-l256 -crc -pass pass:zed s1 s2 s3" \
    || return 1
  $bee2cmd pwd val share:"-pass pass:zed s2 s3 s4 s5" \
    || return 1
  $bee2cmd pwd val share:"-pass pass:zed -crc s2 s3 s4 s5" \
    || return 1
  $bee2cmd pwd print share:"-l128 -pass pass:zed s5 s1 s3" \
    && return 1
  $bee2cmd pwd print share:"-l256 -pass pass:zed s2 s1 s5 s3" \
    || return 1
  $bee2cmd pwd print share:"-pass pass:zed s1 s2 s3 s4 s5" \
    || return 1
  $bee2cmd pwd gen \
    share:"-l192 -pass share:\"-pass pass:zed s1 s2 s3\" ss1 ss2 ss3" \
    || return 1
  $bee2cmd pwd val share:"-pass share:\"-pass pass:zed s1 s2 s2\" ss1 ss2" \
    && return 1
  $bee2cmd pwd val share:"-pass share:\"-pass pass:zed s1 s2 s3\" ss1 ss1" \
    && return 1
  $bee2cmd pwd val share:"-pass share:\"-pass pass:zed s2 s4 s1\" ss3 ss1" \
    || return 1
  $bee2cmd pwd print share:"-pass share:\"-pass pass:zed s2 s4 s1\" ss3 ss1" \
    || return 1
  $bee2cmd pwd print \
    share:"-pass share:\"-pass pass:zed s2 s4 s1\" -crc ss3 ss1" \
    && return 1
  return 0
}

test_kg() {
  rm -rf privkey0 privkey1 privkey2 privkey3 pubkey1 pubkey2 pubkey3 \
    || return 2

  $bee2cmd kg gen -l256 -pass share:"-pass pass:zed s2 s3 s4" \
    && return 1
  $bee2cmd kg gen -l256 -pass share:"-pass pass:zed s2 s3 s4" -pass pass:zed \
    && return 1
  $bee2cmd kg gen -l256 -l192 -pass share:"-pass pass:zed s2 s3 s4" privkey0 \
    && return 1

  $bee2cmd kg gen -l256 -pass share:"-pass pass:zed s2 s3 s4" privkey0 \
    || return 1
  $bee2cmd kg val -pass share:"-pass pass:zed s1 s2 s4" privkey0 \
    || return 1
  $bee2cmd kg chp -passin share:"-pass pass:zed s3 s1 s4" \
    -passout pass:"root" privkey0 \
    || return 1
  $bee2cmd kg print -pass pass:root privkey0 \
    || return 1

  $bee2cmd kg gen -pass pass:trent -l192 privkey1 \
    || return 1
  pubkey1="$($bee2cmd kg print -pass pass:"trent" privkey1)"
  if [ ${#pubkey1} != "192" ]; then
    return 1
  fi

  $bee2cmd kg gen -pass pass:alice privkey2 \
    || return 1
  $bee2cmd kg extr -pass pass:alice privkey2 pubkey2 \
    || return 1
  if [ "$(wc -c pubkey2 | awk '{print $1}')" != "64" ]; then
    return 1
  fi

  $bee2cmd kg gen -l96 -pass pass:bob privkey3 \
    || return 1
  $bee2cmd kg extr -pass pass:bob privkey3 pubkey3 \
    || return 1

  return 0
}

test_cvc() {
  rm -rf cert0 req1 cert1 pubkey1 req2 req21 cert2 req3 cert3 \
    || return 2

  $bee2cmd cvc root -authority BYCA0000 -from 220707 -until 990707 \
    -pass pass:root -eid EEEEEEEEEE -esign 7777 privkey0 cert0 \
    || return 1
  $bee2cmd cvc print cert0 \
    || return 1

  $bee2cmd cvc req -pass pass:trent -authority BYCA0000 -holder BYCA1000 \
    -from 220711 -until 221231 -eid FFFFFFFFFF -esign 7777 privkey1 req1 \
    || return 1
  $bee2cmd cvc print req1 \
    || return 1
  $bee2cmd cvc iss -authority BYCA0000 -pass pass:root privkey0 cert0 \
    req1 cert1 \
    && return 1
  $bee2cmd cvc iss -from 220712 -until 221130 -holder BYCA1023 \
    -eid DDDDDDDDDD -esign BBBB -pass pass:root privkey0 cert0 req1 cert1 \
    || return 1
  $bee2cmd cvc print cert1 \
    || return 1
  $bee2cmd cvc extr cert1 pubkey1 \
    || return 1
  if [ "$(wc -c pubkey1 | awk '{print $1}')" != "96" ]; then
    return 1
  fi

  $bee2cmd cvc req -authority BYCA1023 -from 220712 -until 391231 -esign 1111 \
    -holder "590082394654" -pass pass:alice -eid 8888888888 privkey2 req2 \
    || return 1
  $bee2cmd cvc req -authority BYCA1023 -from 000000 -until 000000 \
    -holder "590082394654" -pass pass:alice privkey2 req21 \
    || return 1
  $bee2cmd cvc iss -pass pass:trent privkey1 cert1 req2 cert2 \
    || return 1
  $bee2cmd cvc match -pass pass:alice privkey2 cert2 \
    || return 1
  $bee2cmd cvc match -pass pass:alisa privkey2 cert2 \
    && return 1
  $bee2cmd cvc print cert2 \
    || return 1
  if [ "$($bee2cmd cvc print -from cert1)" != "220712" ]; then 
    return 1
  fi
  if [ "$($bee2cmd cvc print -until cert1)" != "221130" ]; then 
    return 1
  fi
  if [ "$($bee2cmd cvc print -eid cert1)" != "DDDDDDDDDD" ]; then 
    return 1
  fi
  if [ "$($bee2cmd cvc print -esign cert1)" != "3333" ]; then 
    return 1
  fi

  $bee2cmd cvc val cert0 cert0 \
    || return 1
  $bee2cmd cvc val -date 220707 cert0 cert1 \
    && return 1
  $bee2cmd cvc val -date 220712 cert0 cert1 \
    || return 1
  $bee2cmd cvc val -date 220707 cert0 cert1 cert2 \
    && return 1
  $bee2cmd cvc val -date 220712 cert0 cert1 cert2 \
    || return 1
  $bee2cmd cvc val -date 220712 cert0 cert1 cert2 \
    || return 1
  $bee2cmd cvc val -date 221201 cert0 cert1 cert2 \
    || return 1
  $bee2cmd cvc val -date 400101 cert0 cert1 cert2 \
    && return 1
  $bee2cmd cvc val -date cert0 cert1 cert2 \
    && return 1
  $bee2cmd cvc val cert0 cert1 cert2 \
    || return 1

  $bee2cmd cvc shorten -pass pass:trent -until 391230 privkey1 cert1 cert2 \
    || return 1
  $bee2cmd cvc val cert0 cert1 cert2 \
    || return 1
  if [ "$($bee2cmd cvc print -until cert2)" != "391230" ]; then 
    return 1
  fi

  $bee2cmd cvc req -authority BYCA1023 -from 221030 -until 391231 \
    -holder 590082394655 -pass pass:bob privkey3 req3 \
    || return 1
  $bee2cmd cvc print req3 \
    || return 1
  $bee2cmd cvc iss -pass pass:trent privkey1 cert1 req3 cert3 \
    || return 1

  return 0
}

test_sig(){
  rm -rf ss ff cert01 cert11 cert21 body sig\
    || return 2

  echo test> ff
  echo sig> ss

  $bee2cmd sig val -pubkey pubkey2 ff ss \
    && return 1
  $bee2cmd sig val -anchor cert0 ff ss \
    && return 1
  $bee2cmd sig val -anchor cert2 ff ss \
    && return 1
  $bee2cmd sig val -pubkey pubkey2 ff ff \
    && return 1
  $bee2cmd sig val -anchor cert0 ff ff \
    && return 1
  $bee2cmd sig val -anchor cert2 ff ff \
    && return 1

  rm -rf ss

  $bee2cmd sig sign -date 400101 -certs "cert1 cert2" -pass pass:alice \
    privkey2 ff ss \
    && return 1
  $bee2cmd sig sign -date 230526 -certs "cert1 cert2" -pass pass:alice \
    privkey2 ff ss \
    || return 1

  $bee2cmd sig val -pubkey pubkey2 ff ss \
    || return 1
  $bee2cmd sig val -anchor cert2 ff ss \
    || return 1
  $bee2cmd sig val -anchor cert1 ff ss \
    || return 1

  $bee2cmd sig val -anchor cert0 ff ss \
    && return 1
  $bee2cmd sig sign -certs "cert0 cert1 cert2" -pass pass:alice privkey2 ff ff \
    || return 1

  $bee2cmd sig extr -cert0 ff cert01 \
    || return 1
  diff cert0 cert01 \
    || return 1
  $bee2cmd sig extr -cert1 ff cert11 \
    || return 1
  diff cert1 cert11 \
    || return 1
  $bee2cmd sig extr -cert2 ff cert21 \
    || return 1
  diff cert2 cert21 \
    || return 1
  $bee2cmd sig extr -body ff body \
    || return 1
  if [ $(< body) != "test" ]; then
    return 1
  fi
  $bee2cmd sig extr -sig ff sig \
    || return 1

  $bee2cmd sig val -pubkey pubkey2 ff ff \
    || return 1
  $bee2cmd sig val -anchor cert2 ff ff \
    || return 1
  $bee2cmd sig val -anchor cert1 ff ff \
    || return 1
  $bee2cmd sig val -anchor cert0 ff ff \
    || return 1

  rm -rf ss body

  $bee2cmd sig sign -certs cert2 -pass pass:alice privkey2 ff ss \
    || return 1
  $bee2cmd sig print ss \
    || return 1
  $bee2cmd sig val -pubkey pubkey2 ff ss \
    || return 1
  $bee2cmd sig val -anchor cert2 ff ss \
    || return 1
  $bee2cmd sig val -anchor cert1 ff ss \
    && return 1
  $bee2cmd sig extr -body ss body \
    && return 1

  $bee2cmd sig sign -pass pass:alice -date 230526 privkey2 ff ff \
    || return 1
  $bee2cmd sig val -pubkey pubkey2 ff ff \
    || return 1
  $bee2cmd sig val -anchor cert2 ff ff \
    && return 1
  $bee2cmd sig print ff \
    || return 1

  $bee2cmd sig print ss \
    || return 1
  $bee2cmd sig print -date ss \
    && return 1
  if [ "$($bee2cmd sig print -certc ss)" != "1" ]; then 
    return 1
  fi

  $bee2cmd sig sign -pass pass:bob -certs "cert1 cert3" privkey3 ff ff \
    || return 1
  $bee2cmd sig val -pubkey pubkey3 ff ff \
    || return 1
  $bee2cmd sig val -anchor cert1 ff ff \
    || return 1
  $bee2cmd sig val -anchor cert3 ff ff \
    || return 1

  return 0
}

test_cvr(){
  rm -rf ring2 cert21 cert31 \
    || return 2

  $bee2cmd cvr init -pass pass:alice privkey2 cert2 ring2 \
    || return 1
  $bee2cmd cvr add -pass pass:alice privkey2 cert2 cert3 ring2 \
    || return 1
  $bee2cmd cvr add -pass pass:alice privkey2 cert2 cert3 ring2 \
    && return 1
  $bee2cmd cvr val cert2 ring2 \
    || return 1
  $bee2cmd sig val -anchor cert2 ring2 ring2 \
    || return 1
  $bee2cmd cvr find ring2 cert3 \
    || return 1
  $bee2cmd cvr find ring2 cert2 \
    && return 1
  $bee2cmd cvr extr -cert0 ring2 cert31 \
    || return 1
  diff cert3 cert31 \
    || return 1
  $bee2cmd sig extr -cert0 ring2 cert21 \
    || return 1
  diff cert2 cert21 \
    || return 1
  $bee2cmd cvr print ring2 \
    || return 1
  $bee2cmd cvr print -certc ring2 \
    || return 1
  $bee2cmd sig print ring2 \
    || return 1
  $bee2cmd cvr add -pass pass:alice privkey2 cert2 cert0 ring2 \
    || return 1
  $bee2cmd cvr add -pass pass:alice privkey2 cert2 cert1 ring2 \
    || return 1
  if [ "$($bee2cmd cvr print -certc ring2)" != "3" ]; then 
    return 1
  fi
  $bee2cmd cvr del -pass pass:alice privkey2 cert2 cert1 ring2 \
    || return 1
  $bee2cmd cvr del -pass pass:alice privkey2 cert2 cert0 ring2 \
    || return 1
  $bee2cmd cvr del -pass pass:alice privkey2 cert2 cert0 ring2 \

  return 0
}

test_csr(){
  rm -rf zed.sk1 zed.csr1 \
    || return 2

  $bee2cmd csr val zed.csr \
    || return 1
  $bee2cmd kg gen -pass pass:zed1 zed.sk1 \
    || return 1
  $bee2cmd csr rewrap -pass pass:zed1 zed.sk1 zed.csr zed.csr1 \
    || return 1
  $bee2cmd csr val zed.csr1 \
    || return 1

  return 0
}

test_es() {
  rm -rf dd\
    || return 2

  $bee2cmd es print \
    || return 1
  $bee2cmd es read sys 1 dd \
    || return 1
  if [ "$(wc -c dd | awk '{print $1}')" != "1024" ]; then
    return 1
  fi

  return 0
}

run_test() {
  echo -n "Testing $1... "
  (test_$1 > /dev/null 2>&1)
  if [ $? -eq 0 ]; then 
    echo "Success"
  else 
    echo "Failed"
  fi
} 

run_test ver && run_test bsum && run_test pwd && run_test kg && run_test cvc \
  && run_test sig && run_test cvr && run_test csr && run_test es
