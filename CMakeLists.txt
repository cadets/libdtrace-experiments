cmake_minimum_required(VERSION 3.4)
project(libdtrace-core)

find_library(
	dtrace-core
	NAMES libdtrace-core
	PATHS ./
)

set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libdtrace-core-tests)
set(FILECHECK_TEST_DIR ${TEST_DIR}/filecheck-tests)

file(
	GLOB
	TEST_SRCS
	RELATIVE ${TEST_DIR}
	${TEST_DIR}/*.c
)

file(
	GLOB
	FILECHECK_TEST_SRCS
	RELATIVE ${FILECHECK_TEST_DIR}
	${FILECHECK_TEST_DIR}/*.d
)

if(BUILD_TESTS STREQUAL "yes")
	add_definitions(-D_DTRACE_TESTS)
endif()

add_subdirectory(libdtrace-core)

if(BUILD_TESTS STREQUAL "yes")
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
		set(FILECHECK_TESTS ${TESTS}/filecheck-tests)
		foreach(filecheck_test ${FILECHECK_TEST_SRCS})
			get_filename_component(
				filecheck_test_name
				${FILECHECK_TEST_DIR}/${filecheck_test}
				NAME_WE
			)
			add_test(
				${filecheck_test_name}
				"${FILECHECK_TEST_DIR}/testfilecheck.sh"
				"dtrace -S -e -s"
				"${FILECHECK_TEST_DIR}/${filecheck_test}"
			)
		endforeach()
	endif()
endif()
