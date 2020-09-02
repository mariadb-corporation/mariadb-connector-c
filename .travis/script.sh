#!/bin/bash

set -x
set -e

###################################################################################################################
# test different type of configuration
###################################################################################################################
mysql=( mysql --protocol=tcp -ubob -h127.0.0.1 --port=3305 )

if [ -n "$SKYSQL" ] ; then

  if [ -z "$SKYSQL_TEST_HOST" ] ; then
    echo "No SkySQL configuration found !"
    exit 1
  fi

  export MYSQL_TEST_USER=$SKYSQL_TEST_USER
  export MYSQL_TEST_HOST=$SKYSQL_TEST_HOST
  export MYSQL_TEST_PASSWD=$SKYSQL_TEST_PASSWORD
  export MYSQL_TEST_PORT=$SKYSQL_TEST_PORT
  export MYSQL_TEST_DATABASE=$SKYSQL_TEST_DATABASE
  export MYSQL_TEST_TLS=1
else
  export COMPOSE_FILE=.travis/docker-compose.yml


  ###################################################################################################################
  # launch docker server and maxscale
  ###################################################################################################################
  export INNODB_LOG_FILE_SIZE=$(echo ${PACKET}| cut -d'M' -f 1)0M
  docker-compose -f ${COMPOSE_FILE} build
  docker-compose -f ${COMPOSE_FILE} up -d


  ###################################################################################################################
  # wait for docker initialisation
  ###################################################################################################################

  for i in {60..0}; do
    if echo 'SELECT 1' | "${mysql[@]}" &> /dev/null; then
        break
    fi
    echo 'data server still not active'
    sleep 1
  done

  docker-compose -f ${COMPOSE_FILE} logs

  if [ "$i" = 0 ]; then
    echo 'SELECT 1' | "${mysql[@]}"
    echo >&2 'data server init process failed.'
    exit 1
  fi

  #list ssl certificates
  ls -lrt ${SSLCERT}


  export MYSQL_TEST_HOST=mariadb.example.com
  export MYSQL_TEST_DB=ctest
  export MYSQL_TEST_USER=bob
  export MYSQL_TEST_PORT=3305
  export MYSQL_TEST_TRAVIS=1
  export MARIADB_PLUGIN_DIR=$PWD

fi

#build C connector
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DWITH_SSL=OPENSSL -DCERT_PATH=${SSLCERT}
make

## list ciphers
openssl ciphers -v

###################################################################################################################
# run test suite
###################################################################################################################
echo "Running tests"

cd unittest/libmariadb

ctest -V

