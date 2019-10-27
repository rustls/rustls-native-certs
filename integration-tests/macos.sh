#!/bin/bash

set -ex

reset() {
  echo reset
}

list() {
  cargo test util_list_certs -- --nocapture 2>/dev/null
}

test_distrust_existing_root() {
  list
  reset
}

blorp() {
  security trust-settings-export -s system.dat
  cat system.dat
  security trust-settings-export -d admin.dat
  cat admin.dat
}

reset
test_distrust_existing_root
blorp
printf "\n*** All tests passed ***\n"
