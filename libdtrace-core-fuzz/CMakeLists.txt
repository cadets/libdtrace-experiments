cmake_minimum_required(VERSION 3.4)
project(libdtrace-core-fuzz)

macro(SUBDIRLIST result curdir)
  file(GLOB children RELATIVE ${curdir} ${curdir}/*)
  set(dirlist "")
  foreach(child ${children})
    if(IS_DIRECTORY ${curdir}/${child})
      list(APPEND dirlist ${child})
    endif()
  endforeach()
  set(${result} ${dirlist})
endmacro()

SUBDIRLIST(FUZZ_DIRS ${CMAKE_CURRENT_SOURCE_DIR})

foreach(fuzz_dir ${FUZZ_DIRS})
	add_subdirectory(${fuzz_dir})
endforeach(fuzz_dir)
