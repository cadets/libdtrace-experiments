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
