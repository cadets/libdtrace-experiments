cmake_minimum_required(VERSION 3.4)
project(instruction_input)

add_executable(
	instruction_input
	instruction_input.c
)

target_link_libraries(
	instruction_input
	dtrace-core
)

