#!/bin/bash

set -x
set -e

###################################################################################################################
# test different type of configuration
###################################################################################################################
export MYSQL_TEST_TRAVIS=1

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
  export MYSQL_TEST_HOST=mariadb.example.com
  export MYSQL_TEST_DB=ctest
  export MYSQL_TEST_USER=bob
  export MYSQL_TEST_PORT=3305

  export MARIADB_PLUGIN_DIR=$PWD

  if [ -n "$MAXSCALE_VERSION" ] ; then
      # maxscale ports:
      # - non ssl: 4006
      # - ssl: 4009
      export MYSQL_TEST_PORT=4006
      export MYSQL_TEST_SSL_PORT=4009
      export COMPOSE_FILE=.travis/maxscale-compose.yml
      docker-compose -f ${COMPOSE_FILE} build
  fi

  mysql=( mysql --protocol=TCP -u${MYSQL_TEST_USER} -h${MYSQL_TEST_HOST} --port=${MYSQL_TEST_PORT} ${MYSQL_TEST_DB})

  ###################################################################################################################
  # launch docker server and maxscale
  ###################################################################################################################
  docker-compose -f ${COMPOSE_FILE} up -d

  ###################################################################################################################
  # wait for docker initialisation
  ###################################################################################################################

  for i in {30..0}; do
    if echo 'SELECT 1' | "${mysql[@]}" &> /dev/null; then
        break
    fi
    echo 'data server still not active'
    sleep 2
  done

  if [ "$i" = 0 ]; then
    if echo 'SELECT 1' | "${mysql[@]}" ; then
        break
    fi

    docker-compose -f ${COMPOSE_FILE} logs
    if [ -n "$MAXSCALE_VERSION" ] ; then
        docker-compose -f ${COMPOSE_FILE} exec maxscale tail -n 500 /var/log/maxscale/maxscale.log
    fi
    echo >&2 'data server init process failed.'
    exit 1
  fi

  #list ssl certificates
  ls -lrt ${SSLCERT}

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

