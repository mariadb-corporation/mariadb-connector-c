INCLUDE_DIRECTORIES(${CC_SOURCE_DIR}/zlib)

SET(SOURCE_FILES adler32.c compress.c crc32.c deflate.c gzclose.c gzlib.c gzread.c gzwrite.c infback.c inffast.c inflate.c inftrees.c minigzip.c trees.c uncompr.c zutil.c)

ADD_LIBRARY(zlib STATIC ${SOURCE_FILES})
