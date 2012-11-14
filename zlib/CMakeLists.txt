INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/zlib)

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D_DEBUG")

SET(SOURCE_FILES adler32.c compress.c crc32.c deflate.c example.c gzclose.c gzlib.c gzread.c gzwrite.c infback.c inffast.c inflate.c inftrees.c minigzip.c trees.c uncompr.c zutil.c)

ADD_LIBRARY(zlib ${SOURCE_FILES})
SET_TARGET_PROPERTIES(zlib PROPERTIES  COMPILE_FLAGS
   "${CMAKE_SHARED_LIBRARY_C_FLAGS}")
