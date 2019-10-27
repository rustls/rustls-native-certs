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

reset
test_distrust_existing_root
printf "\n*** All tests passed ***\n"
