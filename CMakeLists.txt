cmake_minimum_required(VERSION 2.8.11)
project(myhttpd)

include(GNUInstallDirs)
find_package(Threads REQUIRED)

set(civetweb_common_files civetweb/src/civetweb.c)
add_library(civetweb_common_objs OBJECT ${civetweb_common_files})
target_include_directories(civetweb_common_objs PRIVATE
	"${CMAKE_SOURCE_DIR}/civetweb/include")
set_property(TARGET civetweb_common_objs
	APPEND PROPERTY COMPILE_DEFINITIONS
		USE_IPV6=1 NO_SSL_DL=1)

set(myhttpd_srcs m.c $<TARGET_OBJECTS:civetweb_common_objs>)
add_executable(myhttpd ${myhttpd_srcs})
target_include_directories(myhttpd PRIVATE
	"${CMAKE_SOURCE_DIR}/civetweb/include")
target_link_libraries(myhttpd ${CMAKE_THREAD_LIBS_INIT}
	ssl crypto)

#refs,
#[threads]
#http://stackoverflow.com/questions/1620918/cmake-and-libpthread
