#!/bin/bash
# =============================================================================
# \brief Testing command-line interface
# \project bee2evp/cmd
# \created 2022.06.24
# \version 2022.07.18
# =============================================================================

bee2cmd=./bee2cmd

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

test_pwd() {
  rm -rf s1 s2 s3 s4 s5 ss1 ss2 ss3 \
    || return 2
  $bee2cmd pwd gen pass:zed \
    || return 1
  $bee2cmd pwd gen pass:"zed" \
    || return 1
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
  $bee2cmd pwd gen share:"-l256 -t3 -pass pass:zed s1 s2 s3 s4 s5" \
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
  $bee2cmd pwd val share:"-pass pass:zed s2 s3 s4 s5" \
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
  return 0
}

test_kg() {
  rm -rf privkey0 privkey1 privkey2 \
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
  pubkey0="$($bee2cmd kg print -pass pass:root privkey0)"
  if [ ${#pubkey0} != "256" ]; then
    return 1
  fi
  $bee2cmd kg gen -pass pass:trent -l192 privkey1 \
    || return 1
  $bee2cmd kg print -pass pass:trent privkey1 \
    || return 1
  $bee2cmd kg gen -pass pass:alice privkey2 \
    || return 1
  return 0
}

test_cvc() {
  rm -rf cert0 cert1 cert2 req1 req2 \
    || return 2
  $bee2cmd cvc root -authority BYCA0000 -from 220707 -until 990707 \
    -pass pass:root -eid EEEEEEEEEE -esign 7777 privkey0 cert0 \
    || return 1
  $bee2cmd cvc print cert0 \
    || return 1
  $bee2cmd cvc req -pass pass:trent  -authority BYCA0000 -holder BYCA1000 \
    -from 220712 -until 221130 -eid DDDDDDDDDD -esign 3333 privkey1 req1 \
    || return 1
  $bee2cmd cvc print req1 \
    || return 1
  $bee2cmd cvc iss -pass pass:root privkey0 cert0 req1 cert1 \
    || return 1
  $bee2cmd cvc print cert1 \
    || return 1
  $bee2cmd cvc req -authority BYCA1000 -from 220712 -until 391231 -esign 1111 \
    -holder "590082394654" -pass pass:alice -eid 8888888888 privkey2 req2 \
    || return 1
  $bee2cmd cvc iss -pass pass:trent privkey1 cert1 req2 cert2 \
    || return 1
  $bee2cmd cvc match -pass pass:alice privkey2 cert2 \
    || return 1
  $bee2cmd cvc match -pass pass:alisa privkey2 cert2 \
    || return 1
  $bee2cmd cvc print cert2 \
    || return 1
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
  return 0
}

test_sig(){
  rm -rf sig_file test_file\
    || return 2
  return 0;
  pubkey2="$($bee2cmd kg print -pass pass:alice privkey2)"
  if [ ${#pubkey2} != "128" ]; then
    return 1
  fi

  echo test > test_file
  echo sig > sig_file

  $bee2cmd sig vfy -pubkey pubkey2 test_file sig_file \
    && return 1
  $bee2cmd sig vfy -anchor cert0 test_file sig_file \
    && return 1
  $bee2cmd sig vfy -anchor cert2 test_file sig_file \
    && return 1
  $bee2cmd sig vfy -pubkey pubkey2 test_file test_file \
    && return 1
  $bee2cmd sig vfy -anchor cert0 test_file test_file \
    && return 1
  $bee2cmd sig vfy -anchor cert2 test_file test_file \
    && return 1

  rm -rf sig_file

  $bee2cmd sig sign -cert cert1,cert2 -pass pass:alice privkey2 test_file sig_file \
    || return 1

  $bee2cmd sig vfy test_file sig_file \
    || return 1
  $bee2cmd sig vfy -pubkey pubkey2 test_file sig_file \
    || return 1
  $bee2cmd sig vfy -anchor cert0 test_file sig_file \
    || return 1
  $bee2cmd sig vfy -anchor cert1 test_file sig_file \
    || return 1
  $bee2cmd sig vfy -anchor cert2 test_file sig_file \
    || return 1
  $bee2cmd sig sign -cert cert1,cert2 -pass pass:alice privkey2 test_file test_file \
    || return 1
  $bee2cmd sig vfy test_file sig_file \
    || return 1
  $bee2cmd sig vfy -pubkey pubkey2 test_file test_file \
    || return 1
  $bee2cmd sig vfy -anchor cert0 test_file test_file \
    || return 1
  $bee2cmd sig vfy -anchor cert1 test_file test_fil \
    || return 1
  $bee2cmd sig vfy -anchor cert2 test_file test_file \
    && return 1

  rm -rf sig_file

  $bee2cmd sig sign -cert cert2 -pass pass:alice privkey2 test_file sig_file \
    || return 1
  $bee2cmd sig vfy -pubkey pubkey2 test_file sig_file \
    || return 1
  $bee2cmd sig vfy -anchor cert1 test_file sig_file \
    || return 1
  $bee2cmd sig vfy -anchor cert2 test_file sig_fil \
    || return 1

  return 0
}

test_pke(){
  rm -rf test_file_decoded test_file_encoded\
      || return 2

  $bee2cmd kg print -pass pass:root privkey0 > pubkey0 \
      || return 1
  $bee2cmd kg print -pass pass:root privkey2 > pubkey2 \
      || return 1

  $bee2cmd pke enc -cert cert0 -pubkey pubkey0 $bee2cmd test_file_encoded \
      || return 1
  $bee2cmd pke dec -pass pass:root privkey0 test_file_encoded test_file_decoded \
      || return 1
  diff $bee2cmd test_file_decoded \
      || return 1
  $bee2cmd pke dec -pass pass:alice privkey2 test_file_encoded test_file_decoded \
      && return 1
  $bee2cmd pke val -cert cert0 -pass pass:root -privkey privkey0 test_file_encoded \
      || return 1
  $bee2cmd pke val -pass pass:root -privkey privkey0 test_file_encoded \
      || return 1
  $bee2cmd pke val -cert cert0 test_file_encoded \
      || return 1
  $bee2cmd pke val test_file_encoded \
      && return 1
  $bee2cmd pke val -cert cert1 test_file_encoded \
      && return 1
  $bee2cmd pke val -pass pass:alice -privkey privkey2 test_file_encoded \
      && return 1

  rm -rf test_file_decoded test_file_encoded \
      || return 2

  $bee2cmd pke enc -cert cert0 -pubkey pubkey0 --itag1024 $bee2cmd test_file_encoded \
      || return 1
  $bee2cmd pke dec -pass pass:root privkey0 test_file_encoded test_file_decoded \
      || return 1
  diff $bee2cmd test_file_decoded \
      || return 1
  $bee2cmd pke val -cert cert0 -pass pass:root -privkey privkey0 test_file_encoded \
      || return 1

  return 0
}

run_test() {
  echo -n "Testing $1... "
  (test_$1 >/dev/null)
  if [ $? -eq 0 ]; then 
    echo "Success"
  else 
    echo "Failed"
  fi
} 

run_test ver && run_test pwd && run_test kg && run_test cvc && run_test sig && run_test pke