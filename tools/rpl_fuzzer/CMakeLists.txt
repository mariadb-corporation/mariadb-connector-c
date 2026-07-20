project(mariadb_fuzzers C)

# Enforce that the fuzzer is compiled using Clang and the correct flags
if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "Fuzzing requires the Clang compiler. Reconfigure with -DCMAKE_C_COMPILER=clang")
endif()

set(FUZZ_FLAGS "-fsanitize=fuzzer,address,undefined -g -fprofile-instr-generate -fcoverage-mapping")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FUZZ_FLAGS}")

add_executable(rpl_fuzzer rpl_fuzzer.c)


target_include_directories(rpl_fuzzer PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/libmariadb
)

#target_link_options(rpl_fuzzer PRIVATE "-Wl,--wrap=malloc" "-Wl,--wrap=calloc")

#  Link against the internal mariadb library target and zlib
# 'mariadb_obj' or 'libmariadb' ensures it links statically or directly to the object files
target_link_libraries(rpl_fuzzer PRIVATE
    libmariadb
    ${SYSTEM_LIBS}
)
