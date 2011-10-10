INCLUDE_DIRECTORIES(BEFORE SYSTEM
                    ${CMAKE_SOURCE_DIR}/include 
                    ${CMAKE_SOURCE_DIR}/libmysql)

ADD_DEFINITIONS(-D ENABLED_LOCAL_INFILE)
ADD_DEFINITIONS(-D HAVE_COMPRESS)

SET(LIBMYSQL_SOURCES array.c bchange.c bmove.c bmove_upp.c mysql_charset.c violite.c net.c charset.c conf_to_src.c ctype.c dbug.c default.c errmsg.c
                     errors.c getopt1.c getopt.c get_password.c getvar.c hash.c int2str.c is_prefix.c libmysql.c list.c 
                     llstr.c longlong2str.c mf_cache.c mf_casecnv.c mf_dirname.c mf_fn_ext.c mf_format.c
                     mf_iocache.c mf_loadpath.c mf_pack.c mf_path.c mf_tempfile.c mf_unixpath.c mf_wcomp.c mulalloc.c 
                     my_alloc.c my_compress.c my_create.c my_delete.c my_div.c my_error.c my_fopen.c my_fstream.c 
                     my_gethostbyname.c my_getwd.c my_init.c my_lib.c my_malloc.c my_messnc.c my_net.c
                     my_once.c my_open.c my_port.c my_pread.c my_pthread.c my_read.c my_realloc.c my_seek.c my_static.c 
                     my_symlink.c my_thr_init.c my_write.c password.c safemalloc.c str2int.c strcend.c strcont.c 
                     strend.c strfill.c string.c strinstr.c strmake.c strmov.c strnlen.c strnmov.c
                     strtoll.c strtoull.c strxmov.c thr_mutex.c typelib.c sha1.c mysql_stmt.c mysql_stmt_codec.c)


ADD_LIBRARY(mysqlclient STATIC ${LIBMYSQL_SOURCES})
TARGET_LINK_LIBRARIES(mysqlclient m zlib)
