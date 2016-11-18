cmake_minimum_required(VERSION 2.8.11)
project(myhttpd)

include(GNUInstallDirs)
find_package(Threads REQUIRED)

set(civetweb_common_files civetweb/src/civetweb.c)
add_library(civetweb_common_objs OBJECT ${civetweb_common_files})
target_include_directories(civetweb_common_objs PRIVATE
	"${CMAKE_BINARY_DIR}/src/include/civetweb")

set(myhttpd_srcs m.c $<TARGET_OBJECTS:civetweb_common_objs>)
add_executable(myhttpd ${myhttpd_srcs})
target_include_directories(myhttpd PRIVATE
	"${CMAKE_BINARY_DIR}/src/include/civetweb")
