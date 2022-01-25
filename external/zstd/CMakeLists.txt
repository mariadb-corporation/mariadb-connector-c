PROJECT(zstd C ASM)


file(GLOB CommonSources lib/common/*.c)
file(GLOB CompressSources lib/compress/*.c)
file(GLOB DecompressSources lib/decompress/*.c ${LIBRARY_DIR}/decompress/*.S)
file(GLOB DictBuilderSources lib/dictBuilder/*.c)

set(zstd_sources
        ${CommonSources}
        ${CompressSources}
        ${DecompressSources}
        ${DictBuilderSources})

INCLUDE_DIRECTORIES(lib)
INCLUDE_DIRECTORIES(lib/common)
INCLUDE_DIRECTORIES(lib/compress)
INCLUDE_DIRECTORIES(lib/decompress)
INCLUDE_DIRECTORIES(lib/dictBuilder)

file(GLOB CommonHeaders lib/common/*.h)
file(GLOB CompressHeaders lib/compress/*.h)
file(GLOB DecompressHeaders lib/decompress/*.h)
file(GLOB DictBuilderHeaders lib/dictBuilder/*.h)

set(zstd_headers
        lib/zstd.h
        ${CommonHeaders}
        ${CompressHeaders}
        ${DecompressHeaders}
        ${DictBuilderHeaders})

ADD_LIBRARY(zstd STATIC ${zstd_sources} ${zstd_headers})
