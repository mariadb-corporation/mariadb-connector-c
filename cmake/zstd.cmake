#
#  Copyright (C) 2011 MariaDB Corporation AB
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the  COPYING-CMAKE-SCRIPTS file.
#

find_path(ZSTD_INCLUDE_DIR NAMES zstd.h)
find_library(ZSTD_LIBRARY_RELEASE NAMES zstd)

include(SelectLibraryConfigurations)
SELECT_LIBRARY_CONFIGURATIONS(ZSTD)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(
    ZSTD DEFAULT_MSG
    ZSTD_LIBRARY ZSTD_INCLUDE_DIR
)
mark_as_advanced(ZSTD_FOUND ZSTD_INCLUDE_DIR ZSTD_LIBRARY)
