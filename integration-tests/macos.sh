#!/bin/bash

set -ex

ANY_CA_PEM=integration-tests/one-existing-ca.pem
ANY_CA_SUBJECT="OU=GlobalSign Root CA - R3, O=GlobalSign, CN=GlobalSign"

reset() {
  security remove-trusted-cert -d $ANY_CA_PEM || true
  list | grep "$ANY_CA_SUBJECT"
}

list() {
  cargo test util_list_certs -- --nocapture 2>/dev/null
}

assert_missing() {
  set +e
  list | grep "$1"
  ret=$?
  set -e
  test $ret -eq 1
}

test_distrust_existing_root() {
  list | grep "$ANY_CA_SUBJECT"
  security add-trusted-cert -d -r deny $ANY_CA_PEM
  assert_missing "$ANY_CA_SUBJECT"
  reset
}

blorp() {
  security dump-trust-settings -s
  security find-certificate -a -p > allcerts.pem
  cat allcerts.pem
  security trust-settings-export -s system.dat
  cat system.dat
  security trust-settings-export -d admin.dat
  cat admin.dat
}

reset
test_distrust_existing_root
blorp
printf "\n*** All tests passed ***\n"
