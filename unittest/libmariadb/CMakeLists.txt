# Copyright (C) 2008 Sun Microsystems, Inc.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

IF(SKIP_TESTS)
  RETURN()
ENDIF()

ENABLE_TESTING()


INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_BINARY_DIR}/include
                    ${CMAKE_SOURCE_DIR}/unittest/mytap)
ADD_DEFINITIONS(-DLIBMARIADB)

SET(API_TESTS "basic-t" "fetch" "charset" "logs" "cursor" "errors" "view" "ps" "ps_bugs" 
              "sp" "result" "connection" "misc" "ps_new" "sqlite3" "thread" "features-10_2" )
IF(WITH_DYNCOL)
  SET(API_TESTS ${API_TESTS} "dyncol")
ENDIF()

SET(API_TESTS ${API_TESTS} "async")

#exclude following tests from ctests, since we need to run them maually with different credentials            
SET(MANUAL_TESTS "t_aurora" "t_conc173")
# Get finger print from server certificate 
IF(WITH_SSL)
  IF(OPENSSL_FOUND)
    #create certificates
    IF(EXISTS "${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs/server-cert.pem")
      MESSAGE(STATUS "certificates already exist")
    ELSE()
      MESSAGE(STATUS "creating certificates")
      IF(WIN32)
        EXECUTE_PROCESS(COMMAND create_certs.bat 
                        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs
                        OUTPUT_FILE x.1 ERROR_FILE x.2)
      ELSE()
        EXECUTE_PROCESS(COMMAND ./create_certs.sh 
                        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs)
      ENDIF()
    ENDIF()

    EXECUTE_PROCESS(COMMAND openssl x509 -in server-cert.pem -sha1 -fingerprint -noout
                    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs
                    OUTPUT_VARIABLE FINGER_PRINT)
    STRING(REPLACE "SHA1 Fingerprint=" "" FINGER_PRINT "${FINGER_PRINT}")
    STRING(REPLACE "\n" "" FINGER_PRINT "${FINGER_PRINT}")
    STRING(REPLACE ":" "" SSL_CERT_FINGER_PRINT "${FINGER_PRINT}")

  ENDIF()
  CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/unittest/libmariadb/ssl.c.in
                 ${CMAKE_SOURCE_DIR}/unittest/libmariadb/ssl.c)
  CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/unittest/libmariadb/fingerprint.list.in
                 ${CMAKE_SOURCE_DIR}/unittest/libmariadb/fingerprint.list)
  SET(API_TESTS ${API_TESTS} "ssl")
ENDIF()

ADD_LIBRARY(ma_getopt ma_getopt.c)

FOREACH(API_TEST ${API_TESTS})
  ADD_EXECUTABLE(${API_TEST} ${API_TEST}.c)
  TARGET_LINK_LIBRARIES(${API_TEST} mytap ma_getopt mariadbclient)
  ADD_TEST(${API_TEST} ${EXECUTABLE_OUTPUT_PATH}/${API_TEST})
  SET_TESTS_PROPERTIES(${API_TEST} PROPERTIES TIMEOUT 120)
ENDFOREACH(API_TEST)

FOREACH(API_TEST ${MANUAL_TESTS})
  ADD_EXECUTABLE(${API_TEST} ${API_TEST}.c)
  TARGET_LINK_LIBRARIES(${API_TEST} mytap ma_getopt mariadbclient)
ENDFOREACH()
