#!/bin/sh

COMPILER=$1
TEST=$2

${COMPILER} ${TEST} 2>&1 | tee ${TEST}.dif | FileCheck ${TEST}
