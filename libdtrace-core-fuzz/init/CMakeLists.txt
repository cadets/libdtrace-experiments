cmake_minimum_required(VERSION 3.4)
project(difo_validate)

add_executable(
	init
	init.c
)

target_link_libraries(
	init	
	dtrace-core
)
