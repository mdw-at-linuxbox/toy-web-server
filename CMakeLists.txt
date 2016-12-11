cmake_minimum_required(VERSION 3.0.2)
project(myhttpd)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH}
"${CMAKE_ROOT}/Modules"
"${CMAKE_SOURCE_DIR}")

#option(USE_SYSTEM_SSL "Use system OpenSSL" OFF)
#if(USE_SYSTEM_SSL)
#endif(USE_SYSTEM_SSL)

find_package(OpenSSL REQUIRED)
find_package(zxid REQUIRED)
find_package(CURL REQUIRED)

include(GNUInstallDirs)
find_package(Threads REQUIRED)

set(civetweb_common_files civetweb/src/civetweb.c)
add_library(civetweb_common_objs OBJECT ${civetweb_common_files})
target_include_directories(civetweb_common_objs PRIVATE
	"${CMAKE_SOURCE_DIR}/civetweb/include")
set_property(TARGET civetweb_common_objs
	APPEND PROPERTY COMPILE_DEFINITIONS
		USE_IPV6=1 NO_SSL_DL=1)

set(myhttpd_srcs m.c p.c s.c z.c $<TARGET_OBJECTS:civetweb_common_objs>)
add_executable(myhttpd ${myhttpd_srcs})
target_include_directories(myhttpd PRIVATE
	"${CMAKE_SOURCE_DIR}/civetweb/include")
#	"${ZXID_INCLUDE_DIR}"
#	"${CURL_INCLUDE_DIRS}"
#	"${OPENSSL_INCLUDE_DIR}")
target_link_libraries(myhttpd ${CMAKE_THREAD_LIBS_INIT}
	zxid
	${CURL_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto z)

#refs,
#[threads]
#http://stackoverflow.com/questions/1620918/cmake-and-libpthread
