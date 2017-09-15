# Copyright (c) 2017 Domagoj Stolfa
# All rights reserved.
#
# This software was developed by BAE Systems, the University of Cambridge
# Computer Laboratory, and Memorial University under DARPA/AFRL contract
# FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
# (TC) research program.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

cmake_minimum_required(VERSION 3.4)
project(libdtrace-core)

find_library(
	dtrace-core
	NAMES libdtrace-core
	PATHS ./
)

if(BUILD_TESTS STREQUAL "yes")
	add_definitions(-D_DTRACE_TESTS)
endif()

add_subdirectory(libdtrace-core)

if(BUILD_TESTS STREQUAL "yes")
	set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libdtrace-core-tests)
	set(FILECHECK_TEST_DIR ${TEST_DIR}/filecheck-tests)

	file(
		GLOB
		TEST_SRCS
		RELATIVE ${TEST_DIR}
		${TEST_DIR}/*.c
	)

	add_subdirectory(libdtrace-core-tests)
	add_subdirectory(libdtrace-core-fuzz)

	enable_testing()
	set(TESTS libdtrace-core-tests)

	foreach(test_source ${TEST_SRCS})
		get_filename_component(test_name ${test_source} NAME_WE)
		add_test(${test_name} ${TESTS}/${test_name})
	endforeach(test_source)

	find_program(
		FILECHECK
		NAMES "FileCheck"
	)

	if(FILECHECK STREQUAL "FILECHECK-NOTFOUND")
		message(WARNING "FileCheck not found, disabling FileCheck tests")
		message(WARNING "Set FILECHECK to the path to FileCheck to enable them")
	else()
		file(
			GLOB
			COMPILER_TEST_SRCS
			RELATIVE ${FILECHECK_TEST_DIR}/compiler
			${FILECHECK_TEST_DIR}/compiler/*.d
		)

		set(COMPILER_TESTS ${TESTS}/filecheck-tests/compiler)
		foreach(compiler_test ${COMPILER_TEST_SRCS})
			get_filename_component(
				compiler_test_name
				${FILECHECK_TEST_DIR}/compiler/${compiler_test}
				NAME_WE
			)
			add_test(
				${compiler_test_name}
				"${FILECHECK_TEST_DIR}/compiler/testfilecheck.sh"
				"dtrace -S -e -s"
				"${FILECHECK_TEST_DIR}/compiler/${compiler_test}"
			)
		endforeach()

		file(
			GLOB
			CTF_TEST_SRCS
			${TEST_DIR}/filecheck-tests/ctf/*.c
		)

		set(CTF_TESTS ${TESTS}/filecheck-tests/ctf)
		foreach(ctf_test ${CTF_TEST_SRCS})
			get_filename_component(
				ctf_test_name
				${ctf_test}
				NAME_WE
			)
			add_test(
				${ctf_test_name}
				"${FILECHECK_TEST_DIR}/ctf/testfilecheck.sh"
				"ctfdump"
				"${TESTS}/filecheck-tests/ctf/${ctf_test_name}.ctf"
				"${FILECHECK_TEST_DIR}/ctf/${ctf_test_name}.fc"
			)
			set_tests_properties(${ctf_test_name} PROPERTIES DEPENDS gen-${ctf_test_name}-ctf)
		endforeach()
	endif()
endif()
