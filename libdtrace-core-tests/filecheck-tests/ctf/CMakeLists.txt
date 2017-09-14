cmake_minimum_required(VERSION 3.4)
project(ctf-tests)

file(
	GLOB
	CTF_SRCS
	RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
	*.c
)

foreach(ctf_src ${CTF_SRCS})
	get_filename_component(ctf_name ${ctf_src} NAME_WE)
	add_custom_command(
		OUTPUT gen-${ctf_name}-obj
		COMMAND ${CMAKE_C_COMPILER} ${CMAKE_C_FLAGS} -O2 -g -c -o ${ctf_name}.o ${CMAKE_CURRENT_SOURCE_DIR}/${ctf_src}
	)
	add_custom_command(
		OUTPUT gen-${ctf_name}-ctf
		COMMAND ctfconvert -L VERSION -o ${ctf_name}.ctf ${CMAKE_CURRENT_BINARY_DIR}/${ctf_name}.o
		DEPENDS gen-${ctf_name}-obj
	)
	add_custom_target("${ctf_name}_ctf" ALL DEPENDS gen-${ctf_name}-obj gen-${ctf_name}-ctf)
endforeach(ctf_src)

