#!/bin/sh

COMMAND=$1
TEST=$2
FILECHECK_PATH=$3

${COMMAND} ${TEST} | tee ${TEST}.ctfdump| FileCheck ${FILECHECK_PATH}
