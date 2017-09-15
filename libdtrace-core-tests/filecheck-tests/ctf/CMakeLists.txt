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
		COMMAND ${CMAKE_C_COMPILER} ${CMAKE_C_FLAGS} -O0 -g -c -o ${ctf_name}.o ${CMAKE_CURRENT_SOURCE_DIR}/${ctf_src}
	)
	add_custom_command(
		OUTPUT gen-${ctf_name}-ctf
		COMMAND ctfconvert -L VERSION -o ${ctf_name}.ctf ${CMAKE_CURRENT_BINARY_DIR}/${ctf_name}.o
		DEPENDS gen-${ctf_name}-obj
	)
	add_custom_target("${ctf_name}_ctf" ALL DEPENDS gen-${ctf_name}-obj gen-${ctf_name}-ctf)
endforeach(ctf_src)

