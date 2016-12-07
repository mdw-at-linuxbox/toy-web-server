#.rst:
# Findzxid
# -----------
#
# Find the zxid encryption library.
#
# Imported Targets
# ^^^^^^^^^^^^^^^^
#
# This module defines the following :prop_tgt:`IMPORTED` targets:
#
# ``zxid``
#   The zxid library, if found.
#
# Result Variables
# ^^^^^^^^^^^^^^^^
#
# This module will set the following variables in your project:
#
# ``ZXID_FOUND``
#   System has the zxid library.
# ``ZXID_INCLUDE_DIR``
#   The zxid include directory.
# ``ZXID_LIBRARY``
#   The zxid library.
# ``ZXID_VERSION``
#   This is set to ``$major.$minor.$revision$patch`` (e.g. ``1.43``).
#
# Hints
# ^^^^^
#
# Set ``ZXID_ROOT_DIR`` to the root directory of an zxid installation.
# Set ``ZXID_USE_STATIC_LIBS`` to ``TRUE`` to look for static libraries.

include(FindPackageHandleStandardArgs)

# Support preference of static libs by adjusting CMAKE_FIND_LIBRARY_SUFFIXES
if(ZXID_USE_STATIC_LIBS)
  set(_zxid_ORIG_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
  if(WIN32)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
  else()
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a )
  endif()
endif()

set(_ZXID_ROOT_HINTS
  ${ZXID_ROOT_DIR}
  ENV ZXID_ROOT_DIR
  )

set(_ZXID_ROOT_HINTS_AND_PATHS
    HINTS ${_ZXID_ROOT_HINTS}
    PATHS ${_ZXID_ROOT_PATHS}
    )

find_path(ZXID_INCLUDE_DIR
  NAMES
    zx/zxid.h
  ${_ZXID_ROOT_HINTS_AND_PATHS}
  HINTS
    ${_ZXID_INCLUDEDIR}
  PATH_SUFFIXES
    include
)



find_library(ZXID_LIBRARY
  NAMES
    zxid
  NAMES_PER_DIR
  ${_ZXID_ROOT_HINTS_AND_PATHS}
  HINTS
    ${_ZXID_LIBDIR}
  PATH_SUFFIXES
    lib
)

function(from_hex HEX DEC)
  string(TOUPPER "${HEX}" HEX)
  set(_res 0)
  string(LENGTH "${HEX}" _strlen)

  while (_strlen GREATER 0)
    math(EXPR _res "${_res} * 16")
    string(SUBSTRING "${HEX}" 0 1 NIBBLE)
    string(SUBSTRING "${HEX}" 1 -1 HEX)
    if (NIBBLE STREQUAL "A")
      math(EXPR _res "${_res} + 10")
    elseif (NIBBLE STREQUAL "B")
      math(EXPR _res "${_res} + 11")
    elseif (NIBBLE STREQUAL "C")
      math(EXPR _res "${_res} + 12")
    elseif (NIBBLE STREQUAL "D")
      math(EXPR _res "${_res} + 13")
    elseif (NIBBLE STREQUAL "E")
      math(EXPR _res "${_res} + 14")
    elseif (NIBBLE STREQUAL "F")
      math(EXPR _res "${_res} + 15")
    else()
      math(EXPR _res "${_res} + ${NIBBLE}")
    endif()

    string(LENGTH "${HEX}" _strlen)
  endwhile()

  set(${DEC} ${_res} PARENT_SCOPE)
endfunction()

if (ZXID_INCLUDE_DIR)
  if(ZXID_INCLUDE_DIR AND EXISTS "${ZXID_INCLUDE_DIR}/zx/zxidvers.h")
    file(STRINGS "${ZXID_INCLUDE_DIR}/zx/zxidvers.h" zxid_version_str
         REGEX "^#[\t ]*define[\t ]+ZXID_VERSION[\t ]+0x([0-9a-fA-F])+.*")

    # The version number is encoded as 0x000MNN: major minor
    # Major and minor translate into the version numbers shown in
    # the string.

    string(REGEX REPLACE "^.*ZXID_VERSION[\t ]+0x00*([0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F]).*$"
           "\\1;\\2" ZXID_VERSION_LIST "${zxid_version_str}")
    list(GET ZXID_VERSION_LIST 0 ZXID_VERSION_MAJOR)
    list(GET ZXID_VERSION_LIST 1 ZXID_VERSION_MINOR)
    from_hex("${ZXID_VERSION_MINOR}" ZXID_VERSION_MINOR)

    set(ZXID_VERSION "${ZXID_VERSION_MAJOR}.${ZXID_VERSION_MINOR}")
  endif ()
endif ()

if (ZXID_VERSION)
  find_package_handle_standard_args(zxid
    REQUIRED_VARS
      ZXID_LIBRARY
      ZXID_INCLUDE_DIR
    VERSION_VAR
      ZXID_VERSION
    FAIL_MESSAGE
      "Could NOT find zxid, try to set the path to zxid root folder in the system variable ZXID_ROOT_DIR"
  )
else ()
  find_package_handle_standard_args(zxid "Could NOT find zxid, try to set the path to zxid root folder in the system variable ZXID_ROOT_DIR"
    ZXID_LIBRARY
    ZXID_INCLUDE_DIR
  )
endif ()

mark_as_advanced(ZXID_INCLUDE_DIR ZXID_LIBRARY)

if(ZXID_FOUND)
  if(NOT TARGET zxid AND EXISTS "${ZXID_LIBRARY}")
    add_library(zxid UNKNOWN IMPORTED)
    set_target_properties(zxid PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${ZXID_INCLUDE_DIR}")
    if(EXISTS "${ZXID_LIBRARY}")
      set_target_properties(zxid PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "C"
        IMPORTED_LOCATION "${ZXID_LIBRARY}")
    endif()
  endif()
endif()

# Restore the original find library ordering
if(ZXID_USE_STATIC_LIBS)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${_zxid_ORIG_CMAKE_FIND_LIBRARY_SUFFIXES})
endif()
