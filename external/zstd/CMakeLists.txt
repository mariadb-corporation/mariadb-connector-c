PROJECT(zstd C)

SET(SOURCE_FILES
lib/common/debug.c
lib/common/pool.c
lib/common/entropy_common.c
lib/common/threading.c
lib/common/error_private.c
lib/common/xxhash.c
lib/common/fse_decompress.c
lib/common/zstd_common.c

lib/compress/fse_compress.c
lib/compress/zstd_double_fast.c
lib/compress/hist.c
lib/compress/zstd_fast.c
lib/compress/huf_compress.c
lib/compress/zstd_lazy.c
lib/compress/zstd_compress.c
lib/compress/zstd_ldm.c
lib/compress/zstd_compress_literals.c
lib/compress/zstdmt_compress.c
lib/compress/zstd_compress_sequences.c
lib/compress/zstd_opt.c
lib/compress/zstd_compress_superblock.c

lib/decompress/huf_decompress.c
lib/decompress/zstd_decompress_block.c
lib/decompress/zstd_ddict.c
lib/decompress/zstd_decompress.c

lib/dictBuilder/cover.c
lib/dictBuilder/fastcover.c
lib/dictBuilder/divsufsort.c
lib/dictBuilder/zdict.c)

INCLUDE_DIRECTORIES(lib/common)

ADD_LIBRARY(zstd STATIC ${SOURCE_FILES})
