cmake_minimum_required(VERSION 3.4)
project(difo_validate)

add_executable(
	difo_validate
	difo_validate.c
)

target_link_libraries(
	difo_validate
	dtrace-core
)
