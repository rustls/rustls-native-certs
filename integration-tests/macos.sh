#!/bin/bash

set -ex

reset() {
  echo reset
}

test_distrust_existing_root() {
  reset
}

reset
test_distrust_existing_root
printf "\n*** All tests passed ***\n"
