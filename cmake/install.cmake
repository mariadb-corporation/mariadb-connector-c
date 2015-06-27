# ************************************************************************************
#   Copyright (C) 2014 MariaDB Corporation Ab
#   
#   This library is free software#; you can redistribute it and/or
#   modify it under the terms of the GNU Library General Public
#   License as published by the Free Software Foundation; either
#   version 2 of the License, or (at your option) any later version.
#   
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Library General Public License for more details.
#   
#   You should have received a copy of the GNU Library General Public
#   License along with this library; if not see <http://www.gnu.org/licenses>
#   or write to the Free Software Foundation, Inc., 
#   51 Franklin St., Fifth Floor, Boston, MA 02110, USA
#
# *************************************************************************************

#
# This file contains settings for the following layouts:
#
# - RPM
# Built with default prefix=/usr
#
#
# The following va+riables are used and can be overwritten
# 
# INSTALL_LAYOUT     installation layout (DEFAULT = standard for tar.gz and zip packages
#                                         RPM packages
#
# BIN_INSTALL_DIR    location of binaries (mariadb_config)
# LIB_INSTALL_DIR    location of libraries
# PLUGIN_INSTALL_DIR location of plugins

IF(NOT INSTALL_LAYOUT)
  SET(INSTALL_LAYOUT "DEFAULT")
ENDIF()

SET(INSTALL_LAYOUT ${INSTALL_LAYOUT} CACHE
  STRING "Installation layout. Currently supported options are DEFAULT (tar.gz and zip) and RPM")

# On Windows we only provide zip and .msi. Latter one uses a different packager. 
IF(UNIX)
  IF(INSTALL_LAYOUT MATCHES "RPM")
    SET(libmariadb_prefix "/usr")
  ELSEIF(INSTALL_LAYOUT MATCHES "DEFAULT")
    SET(libmariadb_prefix ${CMAKE_INSTALL_PREFIX})
  ENDIF()
ENDIF()

IF(CMAKE_DEFAULT_PREFIX_INITIALIZED_BY_DEFAULT)
  SET(CMAKE_DEFAULT_PREFIX ${libmariadb_prefix} CACHE PATH "Installation prefix" FORCE)
ENDIF()

# check if the specified installation layout is valid
SET(VALID_INSTALL_LAYOUTS "DEFAULT" "RPM")
LIST(FIND VALID_INSTALL_LAYOUTS "${INSTALL_LAYOUT}" layout_no)
IF(layout_no EQUAL -1)
  MESSAGE(FATAL_ERROR "Invalid installation layout. Please specify one of the following layouts: ${VALID_INSTALL_LAYOUTS}")
ENDIF()



#
# Todo: We don't generate man pages yet, will fix it
#       later (webhelp to man transformation)
#

#
# DEFAULT layout
#
SET(SUFFIX_INSTALL_DIR_DEFAULT "mariadb")
SET(BIN_INSTALL_DIR_DEFAULT "bin")
SET(LIB_INSTALL_DIR_DEFAULT "lib")
SET(INCLUDE_INSTALL_DIR_DEFAULT "include")
SET(DOCS_INSTALL_DIR_DEFAULT "docs")
SET(PLUGIN_INSTALL_DIR_DEFAULT "lib/plugin")

#
# RPM layout
#
SET(SUFFIX_INSTALL_DIR_RPM "mariadb")
SET(BIN_INSTALL_DIR_RPM "bin")
IF(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
  SET(LIB_INSTALL_DIR_RPM "lib64")
  SET(PLUGIN_INSTALL_DIRDIR_RPM "lib64/plugin")
ELSE()
  SET(LIB_INSTALL_DIR_RPM "lib")
  SET(PLUGIN_INSTALL_DIRDIR_RPM "lib/plugin")
ENDIF()

SET(INCLUDE_INSTALL_DIR_RPM "include")
SET(DOCS_INSTALL_DIR_RPM "docs")
SET(PLUGIN_INSTALL_DIR_RPM "lib/plugin")

#
# Overwrite defaults
#
IF(LIB_INSTALL_DIR)
  SET(LIB_INSTALL_DIR_${INSTALL_LAYOUT} ${LIB_INSTALL_DIR})
ENDIF()

IF(PLUGIN_INSTALL_DIR)
  SET(PLUGIN_INSTALL_DIR_${INSTALL_LAYOUT} ${PLUGIN_INSTALL_DIR})
ENDIF()

IF(INCLUDE_INSTALL_DIR)
  SET(INCLUDE_INSTALL_DIR_${INSTALL_LAYOUT} ${INCLUDE_INSTALL_DIR})
ENDIF()

IF(BIN_INSTALL_DIR)
  SET(BIN_INSTALL_DIR_${INSTALL_LAYOUT} ${BIN_INSTALL_DIR})
ENDIF()

IF(NOT PREFIX_INSTALL_DIR)
  SET(PREFIX_INSTALL_DIR_${INSTALL_LAYOUT} ${libmariadb_prefix})
ELSE()
  SET(PREFIX_INSTALL_DIR_${INSTALL_LAYOUT} ${PREFIX_INSTALL_DIR})
ENDIF()

IF(NOT SUFFIX_INSTALL_DIR)
  SET(SUFFIX_INSTALL_DIR_${INSTALL_LAYOUT} "mariadb")
ELSE()
  SET(SUFFIX_INSTALL_DIR_${INSTALL_LAYOUT} ${SUFFIX_INSTALL_DIR})
ENDIF()

FOREACH(dir "BIN" "LIB" "INCLUDE" "DOCS" "PREFIX" "SUFFIX" "PLUGIN")
  SET(${dir}_INSTALL_DIR ${${dir}_INSTALL_DIR_${INSTALL_LAYOUT}})
  MARK_AS_ADVANCED(${dir}_INSTALL_DIR)
ENDFOREACH()
