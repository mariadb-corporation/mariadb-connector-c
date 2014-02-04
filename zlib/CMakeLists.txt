INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/zlib)

SET(SOURCE_FILES adler32.c compress.c crc32.c deflate.c gzclose.c gzlib.c gzread.c gzwrite.c infback.c inffast.c inflate.c inftrees.c minigzip.c trees.c uncompr.c zutil.c)

ADD_LIBRARY(zlib ${SOURCE_FILES})
SET_TARGET_PROPERTIES(zlib PROPERTIES  COMPILE_FLAGS
   "${CMAKE_SHARED_LIBRARY_C_FLAGS}")

INSTALL(TARGETS
        zlib
        RUNTIME DESTINATION "lib"
        LIBRARY DESTINATION "lib"
        ARCHIVE DESTINATION "lib")
