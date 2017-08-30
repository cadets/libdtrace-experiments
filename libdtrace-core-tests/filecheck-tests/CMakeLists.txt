cmake_minimum_required(VERSION 3.4)

#FIXME: This requires us to have DTrace installed on the system. bad bad bad.

project(dtrace-compiler)

add_definitions(-DNEED_SOLARIS_BOOLEAN)

include_directories(
	/usr/src/cddl/compat/opensolaris/include
	/usr/src/cddl/contrib/opensolaris/lib/libdtrace/common
	/usr/src/cddl/contrib/opensolaris/lib/libctf/common
	/usr/src/cddl/lib/libdtrace
	/usr/src/sys/cddl/compat/opensolaris
	/usr/src/sys/cddl/contrib/opensolaris/uts/common
)

find_library(
	dtrace
	NAMES libdtrace
)

find_library(
	ctf
	NAMES libctf
)

find_library(
	util
	NAMES libutil
)

add_executable(
	compiler
	compiler.c
)

target_link_libraries(
	compiler
	dtrace
	ctf
	util
)
