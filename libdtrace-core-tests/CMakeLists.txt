cmake_minimum_required(VERSION 3.4)
project(libdtrace-core-tests)

if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
	link_directories(/usr/local/lib)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Mac OS X")
elseif(CMAKE_SYSTEM_NAME STREQUAL "illumos")
endif()

set(DTRACE_API ../test-api/dtrace_api.c)

foreach(test_source ${TEST_SRCS})
	get_filename_component(test_name ${test_source} NAME_WE)
	add_executable(
		${test_name}
		${test_source}
		${DTRACE_API}
	)

	target_link_libraries(
		${test_name}
		dtrace-core
	)
endforeach(test_source)

add_subdirectory(compiler)
