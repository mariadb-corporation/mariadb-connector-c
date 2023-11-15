INCLUDE(FetchContent)

FETCHCONTENT_DECLARE(
    zlib
    DOWNLOAD_EXTRACT_TIMESTAMP 1
    # Always use latest stable version
    URL https://zlib.net/current/zlib.tar.gz
)

FETCHCONTENT_MAKEAVAILABLE(zlib)
FETCHCONTENT_GETPROPERTIES(zlib)

if (NOT zlib_POPULATED)
  FETCHCONTENT_POPULATE(zlib)
  ADD_SUBDIRECTORY(${zlib_SOURCE_DIR})
endif()

SET(ZLIB_INCLUDE_DIR ${zlib_SOURCE_DIR} ${zlib_BINARY_DIR})
SET(ZLIB_STATIC_LIB zlibstatic)
