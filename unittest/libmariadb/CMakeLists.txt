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

ENABLE_TESTING()


INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_BINARY_DIR}/include
                    ${CMAKE_SOURCE_DIR}/unittest/mytap)
ADD_DEFINITIONS(-DLIBMARIADB)

SET(API_TESTS "aurora" "async" "basic-t" "fetch" "charset" "logs" "cursor" "errors" "view" "ps" "ps_bugs" 
              "sp" "result" "connection" "misc" "ps_new" "sqlite3" "thread" "dyncol") 

# Get finger print from server certificate 
IF(WITH_SSL)

  #create certificates
  IF(EXISTS "${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs/server-cert.pem")
    MESSAGE(STATUS "certificates already exist")
  ELSE()
    MESSAGE(STATUS "creating certificates")
    EXECUTE_PROCESS(COMMAND openssl req -x509 -newkey rsa:1024 -keyout server-key-enc.pem -out server-cert.pem -subj "/DC=com/DC=example/CN=server" -passout pass:qwerty OUTPUT_FILE x.1 ERROR_FILE x.2 
                    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs)
    EXECUTE_PROCESS(COMMAND openssl rsa -in server-key-enc.pem -out server-key.pem -passin pass:qwerty -passout pass:
      OUTPUT_FILE x.1 ERROR_FILE x.2 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs)
    EXECUTE_PROCESS(COMMAND openssl req -x509 -newkey rsa:1024 -keyout client-key-enc.pem -out client-cert.pem -subj "/DC=com/DC=example/CN=client" -passout pass:qwerty OUTPUT_FILE x.1 ERROR_FILE x.2
                    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs)
    EXECUTE_PROCESS(COMMAND openssl rsa -in client-key-enc.pem -out client-key.pem -passin pass:qwerty -passout pass:
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs OUTPUT_FILE x.1 ERROR_FILE x.2)
    FILE(READ ${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs/server-cert.pem F1)              
    FILE(READ ${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs/client-cert.pem F2)              
    FILE(WRITE ${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs/ca-cert.pem ${F1} ${F2})              
  ENDIF()

  EXECUTE_PROCESS(COMMAND openssl x509 -in server-cert.pem -sha1 -fingerprint -noout
                  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/unittest/libmariadb/certs
                  OUTPUT_VARIABLE FINGER_PRINT)
  STRING(REPLACE "SHA1 Fingerprint=" "" FINGER_PRINT "${FINGER_PRINT}")
  STRING(REPLACE "\n" "" FINGER_PRINT "${FINGER_PRINT}")
  STRING(REPLACE ":" "" SSL_CERT_FINGER_PRINT "${FINGER_PRINT}")

  CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/unittest/libmariadb/ssl.c.in
                 ${CMAKE_SOURCE_DIR}/unittest/libmariadb/ssl.c)
  CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/unittest/libmariadb/fingerprint.list.in
                 ${CMAKE_SOURCE_DIR}/unittest/libmariadb/fingerprint.list)
  SET(API_TESTS ${API_TESTS} "ssl")
ENDIF()

FOREACH(API_TEST ${API_TESTS})
  ADD_EXECUTABLE(${API_TEST} ${API_TEST}.c)
  TARGET_LINK_LIBRARIES(${API_TEST} mytap mariadbclient)
  ADD_TEST(${API_TEST} ${EXECUTABLE_OUTPUT_PATH}/${API_TEST})
  SET_TESTS_PROPERTIES(${API_TEST} PROPERTIES TIMEOUT 120)
ENDFOREACH(API_TEST)
