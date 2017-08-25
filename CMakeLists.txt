cmake_minimum_required(VERSION 3.4)
project(libdtrace-core)

find_library(
	dtrace-core
	NAMES libdtrace-core
	PATHS ./
)

set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libdtrace-core-tests)

file(
	GLOB
	TEST_SRCS
	RELATIVE ${TEST_DIR}
	libdtrace-core-tests/*.c
)

add_definitions(-D_DTRACE_TESTS)

add_subdirectory(libdtrace-core)
add_subdirectory(libdtrace-core-tests)
add_subdirectory(libdtrace-core-fuzz)

enable_testing()
set(TESTS libdtrace-core-tests)

foreach(test_source ${TEST_SRCS})
	get_filename_component(test_name ${test_source} NAME_WE)
	message(STATUS "${test_name}")
	add_test(${test_name} ${TESTS}/${test_name})
endforeach(test_source)
