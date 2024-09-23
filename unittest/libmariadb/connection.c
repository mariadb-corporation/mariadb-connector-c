/*
Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.

The MySQL Connector/C is licensed under the terms of the GPLv2
<http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>, like most
MySQL Connectors. There are special exceptions to the terms and
conditions of the GPLv2 as it is applied to this software, see the
FLOSS License Exception
<http://www.mysql.com/about/legal/licensing/foss-exception.html>.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published
by the Free Software Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/
/**
  Some basic tests of the client API.
*/

#include "my_test.h"

static int test_conc66(MYSQL *my)
{
  MYSQL *mysql= mysql_init(NULL);
  int rc;
  FILE *fp;
  char query[1024];

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  if (!(fp= fopen("./my-conc66-test.cnf", "w")))
    return FAIL;

  fprintf(fp, "[notmygroup]\n");
  fprintf(fp, "user=foo\n");
  fprintf(fp, "[conc-66]\n");
  fprintf(fp, "user=conc66\n");
  fprintf(fp, "port=3306\n");
  fprintf(fp, "enable-local-infile\n");
  fprintf(fp, "server_plugin=file_key_management:file_key_management_algorithm=AES_CTR;file_key_management_key=secret\n");
  fprintf(fp, "password='test@A1\\\";#test'\n");

  fclose(fp);

  rc= mysql_options(mysql, MYSQL_READ_DEFAULT_GROUP, "conc-66");
  check_mysql_rc(rc, mysql);
  rc= mysql_options(mysql, MYSQL_READ_DEFAULT_FILE, "./my-conc66-test.cnf");
  check_mysql_rc(rc, mysql);

  sprintf(query, "GRANT ALL ON %s.* TO 'conc66'@'%s' IDENTIFIED BY 'test@A1\";#test'", schema, this_host ? this_host : "localhost");
  rc= mysql_query(my, query);
  check_mysql_rc(rc, my);
  rc= mysql_query(my, "FLUSH PRIVILEGES");
  check_mysql_rc(rc, my);
  if (!my_test_connect(mysql, hostname, NULL,
                             NULL, schema, port, socketname, 0, 1))
  {
    diag("user: %s", mysql->options.user);
    diag("Error: %s", mysql_error(mysql));
    return FAIL;
  }
    diag("user: %s", mysql->options.user);
  
  sprintf(query, "DROP user 'conc66'@'%s'", this_host ? this_host : "localhost");
  rc= mysql_query(my, query);

  check_mysql_rc(rc, my);
  mysql_close(mysql);
  return OK; 
}

static int test_bug20023(MYSQL *mysql)
{
  int sql_big_selects_orig;
  int max_join_size_orig;

  int sql_big_selects_2;
  int sql_big_selects_3;
  int sql_big_selects_4;
  int sql_big_selects_5;
  int rc;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  if (mysql_get_server_version(mysql) < 50100) {
    diag("Test requires MySQL Server version 5.1 or above");
    return SKIP;
  }

  /***********************************************************************
    Remember original SQL_BIG_SELECTS, MAX_JOIN_SIZE values.
  ***********************************************************************/

  query_int_variable(mysql,
                     "@@session.sql_big_selects",
                     &sql_big_selects_orig);

  query_int_variable(mysql,
                     "@@global.max_join_size",
                     &max_join_size_orig);

  /***********************************************************************
    Test that COM_CHANGE_USER resets the SQL_BIG_SELECTS to the initial value.
  ***********************************************************************/

  /* Issue COM_CHANGE_USER. */
  rc= mysql_change_user(mysql, username, password, schema);
  check_mysql_rc(rc, mysql);

  /* Query SQL_BIG_SELECTS. */

  query_int_variable(mysql,
                     "@@session.sql_big_selects",
                     &sql_big_selects_2);

  /* Check that SQL_BIG_SELECTS is reset properly. */

  FAIL_UNLESS(sql_big_selects_orig == sql_big_selects_2, "Different value for sql_big_select");

  /***********************************************************************
    Test that if MAX_JOIN_SIZE set to non-default value,
    SQL_BIG_SELECTS will be 0.
  ***********************************************************************/

  /* Set MAX_JOIN_SIZE to some non-default value. */

  rc= mysql_query(mysql, "SET @@global.max_join_size = 10000");
  check_mysql_rc(rc, mysql);
  rc= mysql_query(mysql, "SET @@session.max_join_size = default");
  check_mysql_rc(rc, mysql);

  /* Issue COM_CHANGE_USER. */

  rc= mysql_change_user(mysql, username, password, schema);
  check_mysql_rc(rc, mysql);

  /* Query SQL_BIG_SELECTS. */

  query_int_variable(mysql,
                     "@@session.sql_big_selects",
                     &sql_big_selects_3);

  /* Check that SQL_BIG_SELECTS is 0. */

  FAIL_UNLESS(sql_big_selects_3 == 0, "big_selects != 0");

  /***********************************************************************
    Test that if MAX_JOIN_SIZE set to default value,
    SQL_BIG_SELECTS will be 1.
  ***********************************************************************/

  /* Set MAX_JOIN_SIZE to the default value (-1). */

  rc= mysql_query(mysql, "SET @@global.max_join_size = cast(-1 as unsigned int)");
  rc= mysql_query(mysql, "SET @@session.max_join_size = default");

  /* Issue COM_CHANGE_USER. */

  rc= mysql_change_user(mysql, username, password, schema);
  check_mysql_rc(rc, mysql);

  /* Query SQL_BIG_SELECTS. */

  query_int_variable(mysql,
                     "@@session.sql_big_selects",
                     &sql_big_selects_4);

  /* Check that SQL_BIG_SELECTS is 1. */

  FAIL_UNLESS(sql_big_selects_4 == 1, "sql_big_select != 1");

  /***********************************************************************
    Restore MAX_JOIN_SIZE.
    Check that SQL_BIG_SELECTS will be the original one.
  ***********************************************************************/

  rc= mysql_query(mysql, "SET @@global.max_join_size = cast(-1 as unsigned int)");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "SET @@session.max_join_size = default");
  check_mysql_rc(rc, mysql);

  /* Issue COM_CHANGE_USER. */

  rc= mysql_change_user(mysql, username, password, schema);
  check_mysql_rc(rc, mysql);

  /* Query SQL_BIG_SELECTS. */

  query_int_variable(mysql,
                     "@@session.sql_big_selects",
                     &sql_big_selects_5);

  /* Check that SQL_BIG_SELECTS is 1. */

  FAIL_UNLESS(sql_big_selects_5 == sql_big_selects_orig, "big_select != 1");

  /***********************************************************************
    That's it. Cleanup.
  ***********************************************************************/

  return OK;
}

static int test_change_user(MYSQL *mysql)
{
  char buff[256];
  const char *user_pw= "mysqltest_pw";
  const char *user_no_pw= "mysqltest_no_pw";
  const char *pw= "password";
  const char *db= "mysqltest_user_test_database";
  int rc;

  diag("Due to mysql_change_user security fix this test will not work anymore.");
  return(SKIP);

  /* Prepare environment */
  sprintf(buff, "drop database if exists %s", db);
  rc= mysql_query(mysql, buff);
  check_mysql_rc(rc, mysql);

  sprintf(buff, "create database %s", db);
  rc= mysql_query(mysql, buff);
  check_mysql_rc(rc, mysql);

  sprintf(buff,
          "grant select on %s.* to %s@'%%' identified by '%s'",
          db,
          user_pw,
          pw);
  rc= mysql_query(mysql, buff);
  check_mysql_rc(rc, mysql);

  sprintf(buff,
          "grant select on %s.* to %s@'%%'",
          db,
          user_no_pw);
  rc= mysql_query(mysql, buff);
  check_mysql_rc(rc, mysql);


  /* Try some combinations */
  rc= mysql_change_user(mysql, NULL, NULL, NULL);
  FAIL_UNLESS(rc, "Error expected");


  rc= mysql_change_user(mysql, "", NULL, NULL);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, "", "", NULL);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, "", "", "");
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, NULL, "", "");
  FAIL_UNLESS(rc, "Error expected");


  rc= mysql_change_user(mysql, NULL, NULL, "");
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, "", NULL, "");
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, user_pw, NULL, "");
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, user_pw, "", "");
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, user_pw, "", NULL);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, user_pw, NULL, NULL);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, user_pw, "", db);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, user_pw, NULL, db);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, user_pw, pw, db);
  check_mysql_rc(rc, mysql);

  rc= mysql_change_user(mysql, user_pw, pw, NULL);
  check_mysql_rc(rc, mysql);

  rc= mysql_change_user(mysql, user_pw, pw, "");
  check_mysql_rc(rc, mysql);

  rc= mysql_change_user(mysql, user_no_pw, pw, db);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, user_no_pw, pw, "");
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, user_no_pw, pw, NULL);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, user_no_pw, "", NULL);
  check_mysql_rc(rc, mysql);

  rc= mysql_change_user(mysql, user_no_pw, "", "");
  check_mysql_rc(rc, mysql);

  rc= mysql_change_user(mysql, user_no_pw, "", db);
  check_mysql_rc(rc, mysql);

  rc= mysql_change_user(mysql, user_no_pw, NULL, db);
  check_mysql_rc(rc, mysql);

  rc= mysql_change_user(mysql, "", pw, db);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, "", pw, "");
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, "", pw, NULL);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, NULL, pw, NULL);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, NULL, NULL, db);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, NULL, "", db);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, "", "", db);
  FAIL_UNLESS(rc, "Error expected");

  /* Cleanup the environment */

  rc= mysql_change_user(mysql, username, password, schema);
  check_mysql_rc(rc, mysql);

  sprintf(buff, "drop database %s", db);
  rc= mysql_query(mysql, buff);
  check_mysql_rc(rc, mysql);

  sprintf(buff, "drop user %s@'%%'", user_pw);
  rc= mysql_query(mysql, buff);
  check_mysql_rc(rc, mysql);

  sprintf(buff, "drop user %s@'%%'", user_no_pw);
  rc= mysql_query(mysql, buff);
  check_mysql_rc(rc, mysql);

  return OK;
}

/**
  Bug#31669 Buffer overflow in mysql_change_user()
*/

#define LARGE_BUFFER_SIZE 2048

static int test_bug31669(MYSQL *mysql)
{
  int rc;
  static char buff[LARGE_BUFFER_SIZE+1];
  static char user[USERNAME_CHAR_LENGTH+1];
  static char db[NAME_CHAR_LEN+1];
  static char query[LARGE_BUFFER_SIZE*2];

  diag("Due to mysql_change_user security fix this test will not work anymore.");
  return(SKIP);

  rc= mysql_change_user(mysql, NULL, NULL, NULL);
  FAIL_UNLESS(rc, "Error expected");

  rc= mysql_change_user(mysql, "", "", "");
  FAIL_UNLESS(rc, "Error expected");

  memset(buff, 'a', sizeof(buff));

  rc= mysql_change_user(mysql, buff, buff, buff);
  FAIL_UNLESS(rc, "Error expected");

  rc = mysql_change_user(mysql, username, password, schema);
  check_mysql_rc(rc, mysql);

  memset(db, 'a', sizeof(db));
  db[NAME_CHAR_LEN]= 0;
  sprintf(query, "CREATE DATABASE IF NOT EXISTS %s", db);
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);

  memset(user, 'b', sizeof(user));
  user[USERNAME_CHAR_LENGTH]= 0;
  memset(buff, 'c', sizeof(buff));
  buff[LARGE_BUFFER_SIZE]= 0;
  sprintf(query, "GRANT ALL PRIVILEGES ON *.* TO '%s'@'%%' IDENTIFIED BY '%s' WITH GRANT OPTION", user, buff);
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "FLUSH PRIVILEGES");
  check_mysql_rc(rc, mysql);

  rc= mysql_change_user(mysql, user, buff, db);
  check_mysql_rc(rc, mysql);

  user[USERNAME_CHAR_LENGTH-1]= 'a';
  rc= mysql_change_user(mysql, user, buff, db);
  FAIL_UNLESS(rc, "Error expected");

  user[USERNAME_CHAR_LENGTH-1]= 'b';
  buff[LARGE_BUFFER_SIZE-1]= 'd';
  rc= mysql_change_user(mysql, user, buff, db);
  FAIL_UNLESS(rc, "Error expected");

  buff[LARGE_BUFFER_SIZE-1]= 'c';
  db[NAME_CHAR_LEN-1]= 'e';
  rc= mysql_change_user(mysql, user, buff, db);
  FAIL_UNLESS(rc, "Error expected");

  db[NAME_CHAR_LEN-1]= 'a';
  rc= mysql_change_user(mysql, user, buff, db);
  FAIL_UNLESS(!rc, "Error expected");

  rc= mysql_change_user(mysql, user + 1, buff + 1, db + 1);
  FAIL_UNLESS(rc, "Error expected");

  rc = mysql_change_user(mysql, username, password, schema);
  check_mysql_rc(rc, mysql);

  sprintf(query, "DROP DATABASE %s", db);
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);

  sprintf(query, "DELETE FROM mysql.user WHERE User='%s'", user);
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);
  FAIL_UNLESS(mysql_affected_rows(mysql) == 1, "");

  return OK;
}

/**
     Bug# 33831 my_test_connect() should fail if
     given an already connected MYSQL handle.
*/

static int test_bug33831(MYSQL *mysql)
{
  FAIL_IF(my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1), 
         "Error expected");
  
  return OK;
}

/* Test MYSQL_OPT_RECONNECT, Bug#15719 */

static int test_opt_reconnect(MYSQL *mysql)
{
  my_bool my_true= TRUE;
  int rc;
  my_bool reconnect;

  printf("true: %d\n", TRUE);

  mysql= mysql_init(NULL);
  FAIL_IF(!mysql, "not enough memory");

  mysql_get_option(mysql, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_UNLESS(reconnect == 0, "reconnect != 0");

  rc= mysql_options(mysql, MYSQL_OPT_RECONNECT, &my_true);
  check_mysql_rc(rc, mysql);

  mysql_get_option(mysql, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_UNLESS(reconnect == 1, "reconnect != 1");

  if (!(my_test_connect(mysql, hostname, username,
                           password, schema, port,
                           socketname, 0, 1)))
  {
    diag("connection failed");
    mysql_close(mysql);
    return FAIL;
  }

  mysql_get_option(mysql, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_UNLESS(reconnect == 1, "reconnect != 1");

  mysql_close(mysql);

  mysql= mysql_init(NULL);
  FAIL_IF(!mysql, "not enough memory");

  mysql_get_option(mysql, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_UNLESS(reconnect == 0, "reconnect != 0");

  if (!(my_test_connect(mysql, hostname, username,
                           password, schema, port,
                           socketname, 0, 1)))
  {
    diag("connection failed");
    mysql_close(mysql);
    return FAIL;
  }

  mysql_get_option(mysql, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_UNLESS(reconnect == 0, "reconnect != 0");

  mysql_close(mysql);
  return OK;
}


static int test_compress(MYSQL *mysql)
{
  // maxscale doesn't support compression
  MYSQL_RES *res;
  MYSQL_ROW row;
  int rc;
  SKIP_MAXSCALE;

  mysql= mysql_init(NULL);
  FAIL_IF(!mysql, "not enough memory");

  /* use compressed protocol */
  rc= mysql_options(mysql, MYSQL_OPT_COMPRESS, NULL);

  if (!(my_test_connect(mysql, hostname, username,
                           password, schema, port,
                           socketname, 0, 1)))
  {
    diag("connection failed");
    return FAIL;
  }

  rc= mysql_query(mysql, "SHOW STATUS LIKE 'compression'");
  check_mysql_rc(rc, mysql);
  res= mysql_store_result(mysql);
  row= mysql_fetch_row(res);
  FAIL_UNLESS(strcmp(row[1], "ON") == 0, "Compression off");
  mysql_free_result(res);

  mysql_close(mysql);
  return OK;
}

static int test_reconnect(MYSQL *mysql)
{
  my_bool my_true= TRUE;
  MYSQL *mysql1;
  int rc;
  my_bool reconnect;
  SKIP_MAXSCALE;

  mysql1= mysql_init(NULL);
  FAIL_IF(!mysql1, "not enough memory");

  mysql_get_option(mysql1, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_UNLESS(reconnect == 0, "reconnect != 0");

  rc= mysql_options(mysql1, MYSQL_OPT_RECONNECT, &my_true);
  check_mysql_rc(rc, mysql1);

  mysql_get_option(mysql1, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_UNLESS(reconnect == 1, "reconnect != 1");

  if (!(my_test_connect(mysql1, hostname, username,
                           password, schema, port,
                           socketname, 0, 1)))
  {
    diag("connection failed");
    return FAIL;
  }

  mysql_get_option(mysql1, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_UNLESS(reconnect == 1, "reconnect != 1");

  diag("Thread_id before kill: %lu", mysql_thread_id(mysql1));
  mysql_kill(mysql, mysql_thread_id(mysql1));

  mysql_ping(mysql1);

  rc= mysql_query(mysql1, "SELECT 1 FROM DUAL LIMIT 0");
  check_mysql_rc(rc, mysql1);
  diag("Thread_id after kill: %lu", mysql_thread_id(mysql1));

  mysql_get_option(mysql1, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_UNLESS(reconnect == 1, "reconnect != 1");
  mysql_close(mysql1);
  return OK;
}

int test_conc21(MYSQL *mysql)
{
  int rc;
  MYSQL_RES *res= NULL;
  MYSQL_ROW row;
  char tmp[256];
  unsigned int check_server_version= 0;
  int major=0, minor= 0, patch=0;
  SKIP_MAXSCALE;

  if (strlen(mysql_get_server_info(mysql)) > 63)
  {
    diag("server name is too long - skip until rpl hack was removed");
    return SKIP;
  }

  rc= mysql_query(mysql, "SELECT @@version");
  check_mysql_rc(rc, mysql);

  res= mysql_store_result(mysql);
  FAIL_IF(res == NULL, "invalid result set");

  row= mysql_fetch_row(res);
  strcpy(tmp, row[0]);
  mysql_free_result(res);
  
  sscanf(tmp, "%d.%d.%d", &major, &minor, &patch);

  check_server_version= major * 10000 + minor * 100 + patch;

  FAIL_IF(mysql_get_server_version(mysql) != check_server_version, "Numeric server version mismatch");
  FAIL_IF(strcmp(mysql_get_server_info(mysql), tmp) != 0, "String server version mismatch");
  return OK;
}

int test_conc26(MYSQL *unused __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);
  mysql_options(mysql, MYSQL_SET_CHARSET_NAME, "ascii");

  FAIL_IF(my_test_connect(mysql, hostname, "notexistinguser", "password", schema, port, socketname, CLIENT_REMEMBER_OPTIONS, 1),
          "Error expected");
  FAIL_IF(!mysql->options.charset_name || strcmp(mysql->options.charset_name, "ascii") != 0,
          "expected charsetname=ascii");
  mysql_close(mysql);

  mysql= mysql_init(NULL);
  FAIL_IF(my_test_connect(mysql, hostname, "notexistinguser", "password", schema, port, socketname, 0, 1), 
          "Error expected");
  FAIL_IF(mysql->options.charset_name, "Error: options not freed");
  mysql_close(mysql);

  return OK;
}

int test_connection_timeout(MYSQL *unused __attribute__((unused)))
{
  unsigned int timeout= 5;
  time_t start, elapsed;
  MYSQL *mysql= mysql_init(NULL);
  mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (unsigned int *)&timeout);
  start= time(NULL);
  if (my_test_connect(mysql, "192.168.1.101", "notexistinguser", "password", schema, port, socketname, CLIENT_REMEMBER_OPTIONS, 1))
  {
    diag("Error expected - maybe you have to change hostname");
    return FAIL;
  }
  elapsed= time(NULL) - start;
  diag("elapsed: %lu", (unsigned long)elapsed);
  mysql_close(mysql);
  FAIL_IF((unsigned int)elapsed > 2 * timeout, "timeout ignored");
  return OK;
}

int test_connection_timeout2(MYSQL *unused __attribute__((unused)))
{
  unsigned int timeout= 5;
  time_t start, elapsed;
  MYSQL *mysql;
  my_bool no= 0;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;
  SKIP_TLS;

  mysql= mysql_init(NULL);
  mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (unsigned int *)&timeout);
  mysql_options(mysql, MYSQL_INIT_COMMAND, "set @a:=SLEEP(7)");
  mysql_options(mysql, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &no);
  start= time(NULL);
  if (my_test_connect(mysql, hostname, username, password, schema, port, socketname, CLIENT_REMEMBER_OPTIONS, 1))
  {
  elapsed= time(NULL) - start;
  diag("elapsed: %lu", (unsigned long)elapsed);
    diag("timeout error expected");
    return FAIL;
  }
  elapsed= time(NULL) - start;
  diag("elapsed: %lu", (unsigned long)elapsed);
  mysql_close(mysql);
  FAIL_IF((unsigned int)elapsed > 2 * timeout, "timeout ignored");
  return OK;
}

int test_connection_timeout3(MYSQL *unused __attribute__((unused)))
{
  unsigned int timeout= 5;
  unsigned int read_write_timeout= 10;
  int rc;
  time_t start, elapsed;
  MYSQL *mysql= mysql_init(NULL);
  mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (unsigned int *)&timeout);
  mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT, (unsigned int *)&read_write_timeout);
  mysql_options(mysql, MYSQL_OPT_WRITE_TIMEOUT, (unsigned int *)&read_write_timeout);
  mysql_options(mysql, MYSQL_INIT_COMMAND, "set @a:=SLEEP(6)");
  start= time(NULL);
  if (my_test_connect(mysql, hostname, username, password, schema, port, socketname, CLIENT_REMEMBER_OPTIONS, 1))
  {
    diag("timeout error expected");
    elapsed= time(NULL) - start;
    diag("elapsed: %lu", (unsigned long)elapsed);
    return FAIL;
  }
  elapsed= time(NULL) - start;
  diag("elapsed: %lu", (unsigned long)elapsed);
  FAIL_IF((unsigned int)elapsed > timeout + 1, "timeout ignored");

  mysql_close(mysql);
  mysql= mysql_init(NULL);
  mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (unsigned int *)&timeout);
  mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT, (unsigned int *)&read_write_timeout);
  mysql_options(mysql, MYSQL_OPT_WRITE_TIMEOUT, (unsigned int *)&read_write_timeout);

  if (!my_test_connect(mysql, hostname, username, password, schema, port, socketname, CLIENT_REMEMBER_OPTIONS, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    return FAIL;
  }

  start= time(NULL);
  rc= mysql_query(mysql, "SET @a:=SLEEP(12)");
  elapsed= time(NULL) - start;
  diag("elapsed: %lu", (unsigned long)elapsed);
  FAIL_IF(!rc, "timeout expected");
  mysql_close(mysql);
  return OK;
}


/* test should run with valgrind */
static int test_conc118(MYSQL *mysql)
{
  int rc;
  my_bool reconnect= 1;
  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect);

  mysql->options.unused_1= 1;

  rc= mysql_kill(mysql, mysql_thread_id(mysql));

  mysql_ping(mysql);

  rc= mysql_query(mysql, "SET @a:=1");
  check_mysql_rc(rc, mysql);

  FAIL_IF(mysql->options.unused_1 != 1, "options got lost");

  rc= mysql_kill(mysql, mysql_thread_id(mysql));

  mysql_ping(mysql);
  rc= mysql_query(mysql, "SET @a:=1");
  check_mysql_rc(rc, mysql);

  return OK;
}

static int test_wrong_bind_address(MYSQL *unused __attribute__((unused)))
{
  const char *bind_addr= "100.188.111.112";
  MYSQL *mysql;

  if (!hostname || !strcmp(hostname, "localhost"))
  {
    diag("test doesn't work with unix sockets");
    return SKIP;
  }
 
  mysql=  mysql_init(NULL);

  mysql_options(mysql, MYSQL_OPT_BIND, bind_addr);
  if (my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1))
  {
    diag("Error expected");
    mysql_close(mysql);
    return FAIL;
  }
  diag("Error: %s", mysql_error(mysql));
  mysql_close(mysql);
  return OK;
}

static int test_bind_address(MYSQL *my)
{
  MYSQL *mysql;
  char *bind_addr= getenv("MYSQL_TEST_BINDADDR");
  char query[128];
  int rc;

  SKIP_SKYSQL;

  if (!hostname || !strcmp(hostname, "localhost"))
  {
    diag("test doesn't work with unix sockets");
    return SKIP;
  }

  sprintf(query, "DROP USER '%s'@'%s'", username, bind_addr);
  rc= mysql_query(my, query);

  sprintf(query, "CREATE USER '%s'@'%s' IDENTIFIED BY '%s'", username, bind_addr, password);
  rc= mysql_query(my, query);
  check_mysql_rc(rc, my);

  sprintf(query, "GRANT ALL ON %s.* TO '%s'@'%s'", schema, username, bind_addr);
  rc= mysql_query(my, query);
  check_mysql_rc(rc, my);

  if (!bind_addr)
  {
    diag("No bind address specified");
    return SKIP;
  }

  mysql= mysql_init(NULL);
  mysql_options(mysql, MYSQL_OPT_BIND, bind_addr);

  if (!my_test_connect(mysql, bind_addr, username,
                             password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s\n", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }
  diag("%s", mysql_get_host_info(mysql));
  mysql_close(mysql);
  return OK;
}

static int test_get_options(MYSQL *unused __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);
  int options_int[]= {MYSQL_OPT_CONNECT_TIMEOUT, MYSQL_OPT_LOCAL_INFILE,
                      MYSQL_OPT_PROTOCOL, MYSQL_OPT_READ_TIMEOUT, MYSQL_OPT_WRITE_TIMEOUT, 0};
  my_bool options_bool[]= {MYSQL_OPT_RECONNECT, MYSQL_REPORT_DATA_TRUNCATION,
                           MYSQL_OPT_COMPRESS, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, MYSQL_SECURE_AUTH,
#ifdef _WIN32    
    MYSQL_OPT_NAMED_PIPE,
#endif
                          0};
  int options_char[]= {MYSQL_READ_DEFAULT_FILE, MYSQL_READ_DEFAULT_GROUP, MYSQL_SET_CHARSET_NAME,
                       MYSQL_OPT_SSL_KEY, MYSQL_OPT_SSL_CA, MYSQL_OPT_SSL_CERT, MYSQL_OPT_SSL_CAPATH,
                       MYSQL_OPT_SSL_CIPHER, MYSQL_OPT_BIND, MARIADB_OPT_SSL_FP, MARIADB_OPT_SSL_FP_LIST,
                       MARIADB_OPT_TLS_PASSPHRASE, 0};

  const char *init_command[3]= {"SET @a:=1", "SET @b:=2", "SET @c:=3"};
  int elements= 0;
  char **command;


  int intval[2]= {1, 0};
  my_bool boolval[2]= {1, 0};
  const char *char1= "test";
  char *char2;
  int i;
  MYSQL *userdata;
  const char *attr_key[] = {"foo1", "foo2", "foo3"};
  const char *attr_val[] = {"bar1", "bar2", "bar3"};
  char **key, **val;

  for (i=0; i < (int)(sizeof(options_int)/sizeof(int)); i++)
  {
    mysql_options(mysql, options_int[i], &intval[0]);
    intval[1]= 0;
    mysql_get_optionv(mysql, options_int[i], &intval[1]);
    FAIL_IF(intval[0] != intval[1], "mysql_get_optionv (int) failed");
  }
  for (i=0; options_bool[i]; i++)
  {
    mysql_options(mysql, options_bool[i], &boolval[0]);
    intval[1]= 0;
    mysql_get_optionv(mysql, options_bool[i], &boolval[1]);
    FAIL_IF(boolval[0] != boolval[1], "mysql_get_optionv (my_bool) failed");
  }
  for (i=0; options_char[i]; i++)
  {
    mysql_options(mysql, options_char[i], char1);
    char2= NULL;
    mysql_get_optionv(mysql, options_char[i], (void *)&char2);
    if (options_char[i] != MYSQL_SET_CHARSET_NAME) 
      FAIL_IF(strcmp(char1, char2), "mysql_get_optionv (char) failed");
  }

  for (i=0; i < 3; i++)
    mysql_options(mysql, MYSQL_INIT_COMMAND, init_command[i]);

  mysql_get_optionv(mysql, MYSQL_INIT_COMMAND, &command, &elements);
  FAIL_IF(elements != 3, "expected 3 elements");
  for (i=0; i < 3; i++)
    FAIL_IF(strcmp(init_command[i], command[i]), "wrong init command");
  for (i=0; i < 3; i++)
    mysql_optionsv(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, attr_key[i], attr_val[i]);

  mysql_get_optionv(mysql, MYSQL_OPT_CONNECT_ATTRS, NULL, NULL, &elements);
  FAIL_IF(elements != 3, "expected 3 connection attributes");

  key= (char **)malloc(sizeof(char *) * elements);
  val= (char **)malloc(sizeof(char *) * elements);

  mysql_get_optionv(mysql, MYSQL_OPT_CONNECT_ATTRS, &key, &val, &elements);
  for (i=0; i < elements; i++)
  {
    diag("%s => %s", key[i], val[i]);
  }

  free(key);
  free(val);

  mysql_optionsv(mysql, MARIADB_OPT_USERDATA, "my_app", (void *)mysql);
  mysql_get_optionv(mysql, MARIADB_OPT_USERDATA, (char *)"my_app", &userdata);

  FAIL_IF(mysql != userdata, "wrong userdata");
  mysql_close(mysql);
  return OK;
}

static int test_sess_track_db(MYSQL *mysql)
{
  int rc;
  const char *data;
  size_t len;
  char tmp_str[512];


  if (!(mysql->server_capabilities & CLIENT_SESSION_TRACKING))
  {
    diag("Server doesn't support session tracking (cap=%lu)", mysql->server_capabilities);
    return SKIP;
  }

  rc= mysql_query(mysql, "USE mysql");
  check_mysql_rc(rc, mysql);
  FAIL_IF(strcmp(mysql->db, "mysql"), "Expected new schema 'mysql'");

  FAIL_IF(mysql_session_track_get_first(mysql, SESSION_TRACK_SCHEMA, &data, &len),
          "session_track_get_first failed");
  FAIL_IF(strncmp(data, "mysql", len), "Expected new schema 'mysql'");

  sprintf(tmp_str, "USE %s", schema);
  rc= mysql_query(mysql, tmp_str);
  check_mysql_rc(rc, mysql);

  sprintf(tmp_str, "Expected new schema '%s'.", schema);

  FAIL_IF(strcmp(mysql->db, schema), tmp_str);

  FAIL_IF(mysql_session_track_get_first(mysql, SESSION_TRACK_SCHEMA, &data, &len),
          "session_track_get_first failed");
  FAIL_IF(strncmp(data, schema, len), tmp_str);

  if (mysql_get_server_version(mysql) >= 100300)
  {
    diag("charset: %s", mysql->charset->csname);
    rc= mysql_query(mysql, "SET NAMES ascii");
    check_mysql_rc(rc, mysql);
    if (!mysql_session_track_get_first(mysql, SESSION_TRACK_SYSTEM_VARIABLES, &data, &len))
    do {
      printf("# SESSION_TRACK_VARIABLES: %*.*s\n", (int)len, (int)len, data);
    } while (!mysql_session_track_get_next(mysql, SESSION_TRACK_SYSTEM_VARIABLES, &data, &len));
    diag("charset: %s", mysql->charset->csname);
    FAIL_IF(strcmp(mysql->charset->csname, "ascii"),
            "Expected charset 'ascii'");

    rc= mysql_query(mysql, "SET NAMES latin1");
    check_mysql_rc(rc, mysql);
    FAIL_IF(strcmp(mysql->charset->csname, "latin1"), "Expected charset 'latin1'");
  }
  rc= mysql_query(mysql, "CREATE PROCEDURE p1() "
                         "BEGIN "
                         "SET @@autocommit=0; "
                         "SET NAMES utf8; "
                         "SET session auto_increment_increment=2; "
                         "END ");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "CALL p1()");
  check_mysql_rc(rc, mysql);

  if (!mysql_session_track_get_first(mysql, SESSION_TRACK_SYSTEM_VARIABLES, &data, &len))
  do {
    printf("# SESSION_TRACK_VARIABLES: %*.*s\n", (int)len, (int)len, data);
  } while (!mysql_session_track_get_next(mysql, SESSION_TRACK_SYSTEM_VARIABLES, &data, &len));

  rc= mysql_query(mysql, "DROP PROCEDURE IF EXISTS p1");
  check_mysql_rc(rc, mysql);

  return OK;
}

static int test_conc496(MYSQL *mysql)
{
  int rc;
  const char *data;
  size_t len;

  rc= mysql_query(mysql, "set @@session.session_track_transaction_info=STATE");

  if (rc && mysql_errno(mysql) == ER_UNKNOWN_SYSTEM_VARIABLE)
  {
    diag("session_track_transaction_info not supported");
    return SKIP;
  }

  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "BEGIN");
  check_mysql_rc(rc, mysql);
  if (!mysql_session_track_get_first(mysql, SESSION_TRACK_TRANSACTION_STATE, &data, &len))
  do {
    FAIL_IF(len != 8, "expected 8 bytes");
    FAIL_IF(data[0] != 'T', "expected transaction");
  } while (!mysql_session_track_get_next(mysql, SESSION_TRACK_TRANSACTION_STATE, &data, &len));

  rc= mysql_query(mysql, "CREATE TEMPORARY TABLE t1(a int) ENGINE=InnoDB");
  check_mysql_rc(rc, mysql);
  rc= mysql_query(mysql, "COMMIT");
  
  check_mysql_rc(rc, mysql);

  if (!mysql_session_track_get_first(mysql, SESSION_TRACK_TRANSACTION_STATE, &data, &len))
  do {
    FAIL_IF(len != 8, "expected 8 bytes");
    FAIL_IF(data[0] != '_', "expected underscore");
  } while (!mysql_session_track_get_next(mysql, SESSION_TRACK_TRANSACTION_STATE, &data, &len));

  return OK;
}


static int test_unix_socket_close(MYSQL *unused __attribute__((unused)))
{
#ifdef _WIN32
  diag("test does not run on Windows");
  return SKIP;
#else
  MYSQL *mysql= mysql_init(NULL);
  FILE *fp;
  int i;

  SKIP_SKYSQL;
  SKIP_TRAVIS();

  if (!(fp= fopen("./dummy_sock", "w")))
  {
    diag("couldn't create dummy socket");
    return FAIL;
  }
  fclose(fp);

  for (i=0; i < 10000; i++)
  {
    my_test_connect(mysql, "localhost", "user", "passwd", NULL, 0, "./dummy_sock", 0, 1);
    /* check if we run out of sockets */
    if (mysql_errno(mysql) == 2001)
    {
      diag("out of sockets after %d attempts", i);
      mysql_close(mysql);
      return FAIL;
    }
  }
  mysql_close(mysql);
  return OK;
#endif
}


static int test_reset(MYSQL *mysql)
{
  int rc;
  MYSQL_RES *res;

  if (mysql_get_server_version(mysql) < 100200)
    return SKIP;

  rc= mysql_query(mysql, "DROP TABLE IF EXISTS t1");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "CREATE TABLE t1 (a int)");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "INSERT INTO t1 VALUES (1),(2),(3)");
  check_mysql_rc(rc, mysql);

  FAIL_IF(mysql_affected_rows(mysql) != 3, "Expected 3 rows");

  rc= mysql_reset_connection(mysql);
  check_mysql_rc(rc, mysql);

  FAIL_IF(mysql_affected_rows(mysql) != ~(my_ulonglong)0, "Expected 0 rows");

  rc= mysql_query(mysql, "SELECT a FROM t1");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "SELECT 1 FROM DUAL");
  FAIL_IF(!rc, "Error expected"); 

  rc= mysql_reset_connection(mysql);
  check_mysql_rc(rc, mysql);

  res= mysql_store_result(mysql);
  FAIL_IF(res, "expected no result");

  rc= mysql_query(mysql, "SELECT a FROM t1");
  check_mysql_rc(rc, mysql);

  res= mysql_use_result(mysql);
  FAIL_IF(!res, "expected result");

  rc= mysql_reset_connection(mysql);
  check_mysql_rc(rc, mysql);

  FAIL_IF(mysql_fetch_row(res), "expected error");

  mysql_free_result(res);

  rc= mysql_query(mysql, "DROP TABLE t1");
  check_mysql_rc(rc, mysql);

  return OK;
}

static int test_auth256(MYSQL *my)
{
  MYSQL *mysql= mysql_init(NULL);
  int rc;
  MYSQL_RES *res;
  my_ulonglong num_rows= 0;
  char query[1024];
  SKIP_MAXSCALE;

  if (IS_SKYSQL(hostname))
    return SKIP;

  // xpand doesn't have information_schema.plugins
  SKIP_XPAND;

  if (!mysql_client_find_plugin(mysql, "sha256_password", MYSQL_CLIENT_AUTHENTICATION_PLUGIN))
  {
    diag("sha256_password plugin not available");
    mysql_close(mysql);
    return SKIP;
  }

  rc= mysql_query(my, "SELECT * FROM information_schema.plugins where plugin_name='sha256_password'");
  check_mysql_rc(rc, mysql);

  res= mysql_store_result(my);
  num_rows= mysql_num_rows(res);
  mysql_free_result(res);

  if (!num_rows)
  {
    diag("server doesn't support sha256 authentication");
    mysql_close(mysql);
    return SKIP;
  }

  rc= mysql_query(my, "DROP USER IF EXISTS sha256user@localhost");
  check_mysql_rc(rc, mysql);

  sprintf(query, "CREATE user 'sha256user'@'%s' identified with sha256_password by 'foo'", this_host);
  rc= mysql_query(my, query);
  check_mysql_rc(rc, my);

  if (!my_test_connect(mysql, hostname, "sha256user", "foo", NULL, port, socketname, 0, 1))
  {
    diag("error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }
  mysql_close(mysql);

  mysql= mysql_init(NULL);
  mysql_options(mysql, MYSQL_SERVER_PUBLIC_KEY, "rsa_public_key.pem");
  if (!my_test_connect(mysql, hostname, "sha256user", "foo", NULL, port, socketname, 0, 1))
  {
    diag("error: %s", mysql_error(mysql));
    diag("host: %s", this_host);
    mysql_close(mysql);
    return FAIL;
  }
  mysql_close(mysql);
  sprintf(query, "DROP USER 'sha256user'@'%s'", this_host);
  rc= mysql_query(my, query);
  check_mysql_rc(rc, mysql);
  return OK;
}

static int test_mdev13100(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);
  int rc;
  FILE *fp;

  /* MXS-4898: MaxScale sends utf8mb4 in handshake OK packet */
  SKIP_MAXSCALE;

  if (!(fp= fopen("./mdev13100.cnf", "w")))
    return FAIL;

   /* [client] group only */
  fprintf(fp, "[client]\n");
  fprintf(fp, "default-character-set=latin2\n");

  fclose(fp);

  rc= mysql_options(mysql, MYSQL_READ_DEFAULT_FILE, "./mdev13100.cnf");
  check_mysql_rc(rc, mysql);

  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    return FAIL;
  }
  diag("Default charset: %s", mysql_character_set_name(mysql));
  FAIL_IF(strcmp("latin2", mysql_character_set_name(mysql)), "Expected charset latin2");
  mysql_close(mysql);

  /* value from client-mariadb group */
  mysql= mysql_init(NULL);
  if (!(fp= fopen("./mdev13100.cnf", "w")))
    return FAIL;

  fprintf(fp, "[client]\n");
  fprintf(fp, "default-character-set=latin1\n");
  fprintf(fp, "[client-server]\n");
  fprintf(fp, "default-character-set=latin2\n");

  fclose(fp);

  rc= mysql_options(mysql, MYSQL_READ_DEFAULT_FILE, "./mdev13100.cnf");
  check_mysql_rc(rc, mysql);

  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    return FAIL;
  }
  FAIL_IF(strcmp("latin2", mysql_character_set_name(mysql)), "Expected charset latin2");
  mysql_close(mysql);

/* values from client-mariadb group */
  mysql= mysql_init(NULL);

if (!(fp= fopen("./mdev13100.cnf", "w")))
    return FAIL;

  fprintf(fp, "[client]\n");
  fprintf(fp, "default-character-set=latin1\n");
  fprintf(fp, "[client-server]\n");
  fprintf(fp, "default-character-set=utf8\n");
  fprintf(fp, "[client-mariadb]\n");
  fprintf(fp, "default-character-set=latin2\n");

  fclose(fp);

  rc= mysql_options(mysql, MYSQL_READ_DEFAULT_FILE, "./mdev13100.cnf");
  check_mysql_rc(rc, mysql);

  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    return FAIL;
  }
  FAIL_IF(strcmp("latin2", mysql_character_set_name(mysql)), "Expected charset latin2");
  mysql_close(mysql);

/* values from mdev-13100 group */
  mysql= mysql_init(NULL);
  if (!(fp= fopen("./mdev13100.cnf", "w")))
    return FAIL;

  fprintf(fp, "[client]\n");
  fprintf(fp, "default-character-set=latin1\n");
  fprintf(fp, "[client-server]\n");
  fprintf(fp, "default-character-set=latin1\n");
  fprintf(fp, "[client-mariadb]\n");
  fprintf(fp, "default-character-set=utf8\n");
  fprintf(fp, "[mdev13100]\n");
  fprintf(fp, "default-character-set=latin2\n");

  fclose(fp);

  rc= mysql_options(mysql, MYSQL_READ_DEFAULT_FILE, "./mdev13100.cnf");
  check_mysql_rc(rc, mysql);
  rc= mysql_options(mysql, MYSQL_READ_DEFAULT_GROUP, "mdev13100");
  check_mysql_rc(rc, mysql);

  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    return FAIL;
  }
  FAIL_IF(strcmp("latin2", mysql_character_set_name(mysql)), "Expected charset latin2");
  mysql_close(mysql);

/* values from [programname] group */
  mysql= mysql_init(NULL);
  if (!(fp= fopen("./mdev13100.cnf", "w")))
    return FAIL;

  fprintf(fp, "[client]\n");
  fprintf(fp, "default-character-set=utf8\n");
  fprintf(fp, "[client-server]\n");
  fprintf(fp, "default-character-set=utf8\n");
  fprintf(fp, "[client-mariadb]\n");
  fprintf(fp, "default-character-set=latin2\n");

  fclose(fp);

  rc= mysql_options(mysql, MYSQL_READ_DEFAULT_FILE, "./mdev13100.cnf");
  check_mysql_rc(rc, mysql);
  rc= mysql_options(mysql, MYSQL_READ_DEFAULT_GROUP, "");
  check_mysql_rc(rc, mysql);

  if (!my_test_connect(mysql, hostname, username,
                             password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    return FAIL;
  }
  diag("character set: %s", mysql_character_set_name(mysql));
  FAIL_IF(strcmp("latin2", mysql_character_set_name(mysql)), "Expected charset latin2");
  mysql_close(mysql);

  remove("./mdev13100.cnf");

  return OK;
}

static int test_conc276(MYSQL *unused __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);
  int rc;
  my_bool val= 1;

  mysql_options(mysql, MYSQL_OPT_SSL_ENFORCE, &val);
  mysql_options(mysql, MYSQL_OPT_RECONNECT, &val);

  if (!my_test_connect(mysql, hostname, username, password, schema, port, socketname, 0, 1))
  {
    diag("Connection failed. Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }
  diag("Cipher in use: %s", mysql_get_ssl_cipher(mysql));
  rc= mariadb_reconnect(mysql);
  check_mysql_rc(rc, mysql);

  diag("Cipher in use: %s", mysql_get_ssl_cipher(mysql));
  /* this shouldn't crash anymore */
  rc= mysql_query(mysql, "SET @a:=1");
  check_mysql_rc(rc, mysql);

  mysql_close(mysql);
  return OK;
}

static int test_expired_pw(MYSQL *my)
{
  MYSQL *mysql;
  int rc;
  char query[512];
  unsigned char expire= 1;

  if (mariadb_connection(my) ||
     !(my->server_capabilities & CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS))
  {
    diag("Server doesn't support password expiration");
    return SKIP;
  }
  sprintf(query, "DROP USER 'foo'@'%s'", this_host);
  rc= mysql_query(my, query);

  sprintf(query, "CREATE USER 'foo'@'%s' IDENTIFIED BY 'foo'", this_host);
  rc= mysql_query(my, query);
  check_mysql_rc(rc, my);

  sprintf(query, "GRANT ALL ON *.* TO 'foo'@'%s'", this_host);
  rc= mysql_query(my, query);
  check_mysql_rc(rc, my);

  sprintf(query, "ALTER USER 'foo'@'%s' PASSWORD EXPIRE", this_host);
  rc= mysql_query(my, query);
  check_mysql_rc(rc, my);

  mysql= mysql_init(NULL);

  my_test_connect(mysql, hostname, "foo", "foo", schema,
                  port, socketname, 0, 1);

  FAIL_IF(!mysql_errno(mysql), "Error expected");
  mysql_close(mysql);

  mysql= mysql_init(NULL);
  mysql_optionsv(mysql, MYSQL_OPT_CAN_HANDLE_EXPIRED_PASSWORDS, &expire);

  my_test_connect(mysql, hostname, "foo", "foo", schema,
                  port, socketname, 0, 1);

  /* we should be in sandbox mode now, only set commands should be allowed */
  rc= mysql_query(mysql, "DROP TABLE IF EXISTS t1");
  FAIL_IF(!rc, "Error expected (we are in sandbox mode");

  diag("error: %d %s", mysql_errno(mysql), mysql_error(mysql));
  FAIL_IF(mysql_errno(mysql) != ER_MUST_CHANGE_PASSWORD &&
          mysql_errno(mysql) != ER_MUST_CHANGE_PASSWORD_LOGIN, "Error 1820/1862 expected");

  mysql_close(mysql);

  sprintf(query, "DROP USER 'foo'@'%s'", this_host);
  rc= mysql_query(my, query);
  check_mysql_rc(rc, my);

  return OK;
}

static int test_conc315(MYSQL *mysql)
{
  int rc;
  const char *csname;
  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  mysql_get_optionv(mysql, MYSQL_SET_CHARSET_NAME, (void *)&csname);
  diag("csname=%s", csname);
  FAIL_UNLESS(strcmp(csname, MARIADB_DEFAULT_CHARSET) == 0, "Wrong default character set");

  rc= mysql_change_user(mysql, username, password, schema);
  check_mysql_rc(rc, mysql);
  mysql_get_optionv(mysql, MYSQL_SET_CHARSET_NAME, (void *)&csname);
  FAIL_UNLESS(strcmp(csname, MARIADB_DEFAULT_CHARSET) == 0, "Wrong default character set");
  return OK;
}
#ifndef WIN32
static int test_conc317(MYSQL *unused __attribute__((unused)))
{
  MYSQL *mysql;
  my_bool reconnect = 0;
  FILE *fp= NULL;
  const char *env= getenv("MYSQL_TMP_DIR");
  char cnf_file1[FN_REFLEN + 1];

  SKIP_SKYSQL;

  if (travis_test)
    return SKIP;

  if (!env)
    env= "/tmp";

  setenv("HOME", env, 1);

  snprintf(cnf_file1, FN_REFLEN, "%s%c.my.cnf", env, FN_LIBCHAR);

  FAIL_IF(!access(cnf_file1, R_OK), "access");

  mysql= mysql_init(NULL);
  fp= fopen(cnf_file1, "w");
  FAIL_IF(!fp, "fopen");

  fprintf(fp, "[client]\ndefault-character-set = latin2\nreconnect= 1\n");
  fclose(fp);

  mysql_options(mysql, MYSQL_READ_DEFAULT_GROUP, "");
  my_test_connect(mysql, hostname, username, password,
                  schema, port, socketname, 0, 1);

  remove(cnf_file1);

  FAIL_IF(strcmp(mysql_character_set_name(mysql), "latin2"), "expected charset latin2");
  mysql_get_optionv(mysql, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_IF(reconnect != 1, "expected reconnect=1");
  mysql_close(mysql);
  return OK;
}

static int test_conc327(MYSQL *unused __attribute__((unused)))
{
  MYSQL *mysql;
  my_bool reconnect = 0;
  FILE *fp1= NULL, *fp2= NULL;
  const char *env= getenv("MYSQL_TMP_DIR");
  char cnf_file1[FN_REFLEN + 1];
  char cnf_file2[FN_REFLEN + 1];

  SKIP_SKYSQL;

  if (travis_test)
    return SKIP;

  if (!env)
    env= "/tmp";

  setenv("HOME", env, 1);

  snprintf(cnf_file1, FN_REFLEN, "%s%c.my.cnf", env, FN_LIBCHAR);
  snprintf(cnf_file2, FN_REFLEN, "%s%c.my.tmp", env, FN_LIBCHAR);

  FAIL_IF(!access(cnf_file1, R_OK), "access");

  fp1= fopen(cnf_file1, "w");
  fp2= fopen(cnf_file2, "w");
  FAIL_IF(!fp1 || !fp2, "fopen failed");

  fprintf(fp1, "!include %s\n", cnf_file2);
  
  fprintf(fp2, "[client]\ndefault-character-set = latin2\nreconnect= 1\n");
  fclose(fp1);
  fclose(fp2);

  mysql= mysql_init(NULL);
  mysql_options(mysql, MYSQL_READ_DEFAULT_GROUP, "");
  my_test_connect(mysql, hostname, username, password,
                  schema, port, socketname, 0, 1);

  remove(cnf_file1);
  remove(cnf_file2);

  diag("new charset: %s", mysql->options.charset_name);
  FAIL_IF(strcmp(mysql_character_set_name(mysql), "latin2"), "expected charset latin2");
  mysql_get_optionv(mysql, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_IF(reconnect != 1, "expected reconnect=1");
  mysql_close(mysql);

  snprintf(cnf_file1, FN_REFLEN, "%s%cmy.cnf", env, FN_LIBCHAR);
  fp1= fopen(cnf_file1, "w");
  fp2= fopen(cnf_file2, "w");
  FAIL_IF(!fp1 || !fp2, "fopen failed");

  fprintf(fp2, "!includedir %s\n", env);
  
  fprintf(fp1, "[client]\ndefault-character-set = latin2\nreconnect= 1\n");
  fclose(fp1);
  fclose(fp2);
  mysql= mysql_init(NULL);
  mysql_options(mysql, MYSQL_READ_DEFAULT_FILE, cnf_file2);
  my_test_connect(mysql, hostname, username, password,
                  schema, port, socketname, 0, 1);

  remove(cnf_file1);
  remove(cnf_file2);

  FAIL_IF(strcmp(mysql_character_set_name(mysql), "latin2"), "expected charset latin2");
  mysql_get_optionv(mysql, MYSQL_OPT_RECONNECT, &reconnect);
  FAIL_IF(reconnect != 1, "expected reconnect=1");
  mysql_close(mysql);

  return OK;
}
#endif

static int test_conc332(MYSQL *unused __attribute__((unused)))
{
  int rc;
  MYSQL *mysql= mysql_init(NULL);
  int server_status1, server_status2;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  mysql_options(mysql, MYSQL_SET_CHARSET_NAME, "utf8mb4");

  my_test_connect(mysql, hostname, username, password, schema,
                  port, socketname, 0, 1);

  FAIL_IF(mysql_errno(mysql), "Error during connect");

  mariadb_get_infov(mysql, MARIADB_CONNECTION_SERVER_STATUS, &server_status1);
  diag("server_status: %d", server_status1);

  if (server_status1 & SERVER_STATUS_AUTOCOMMIT)
    rc= mysql_query(mysql, "SET autocommit= 0");
  else
    rc= mysql_query(mysql, "SET autocommit= 1");
  check_mysql_rc(rc, mysql);
  mariadb_get_infov(mysql, MARIADB_CONNECTION_SERVER_STATUS, &server_status2);
  diag("server_status after changing autocommit: %d", server_status2);

  rc= mysql_change_user(mysql, username, password, schema);
  check_mysql_rc(rc, mysql);

  mariadb_get_infov(mysql, MARIADB_CONNECTION_SERVER_STATUS, &server_status2);
  diag("server_status after mysql_change_user: %d", server_status2);
  if (server_status1 != server_status2)
  {
    diag("Expected server_status %d instead of %d", server_status1, server_status2);
    mysql_close(mysql);
    return FAIL;
  }
  mysql_close(mysql);
  return OK;
}

static int test_conc351(MYSQL *unused __attribute__((unused)))
{
  int rc;
  const char *data;
  size_t len;
  MYSQL *mysql= mysql_init(NULL);
  ulong capabilities= 0;

  my_test_connect(mysql, hostname, username, password, schema,
                  port, socketname, 0, 1);

  FAIL_IF(mysql_errno(mysql), "Error during connect");

  mariadb_get_infov(mysql, MARIADB_CONNECTION_SERVER_CAPABILITIES, &capabilities);
  if (!(capabilities & CLIENT_SESSION_TRACKING))
  {
    mysql_close(mysql);
    diag("Server doesn't support session tracking (cap=%lu)", mysql->server_capabilities);
    return SKIP;
  }
  rc= mysql_query(mysql, "USE mysql");
  check_mysql_rc(rc, mysql);
  FAIL_IF(strcmp(mysql->db, "mysql"), "Expected new schema 'mysql'");

  FAIL_IF(mysql_session_track_get_first(mysql, SESSION_TRACK_SCHEMA, &data, &len), "expected session track schema");

  rc= mysql_query(mysql, "SET @a:=1");
  check_mysql_rc(rc, mysql);

  FAIL_IF(!mysql_session_track_get_first(mysql, SESSION_TRACK_SCHEMA, &data, &len), "expected no schema tracking information");

  mysql_close(mysql);
  return OK;
}

static int test_conc312(MYSQL *my)
{
  int rc;
  char query[1024];
  MYSQL *mysql;

  sprintf(query, "DROP USER 'foo'@'%s'", this_host);
  rc= mysql_query(my, query);

  sprintf(query, "CREATE USER 'foo'@'%s' IDENTIFIED WITH caching_sha2_password BY 'foo'", this_host);
  rc= mysql_query(my, query);

  if (rc)
  {
    diag("Error: %s", mysql_error(my));
    diag("caching_sha256_password not supported");
    return SKIP; 
  }

  sprintf(query, "GRANT ALL ON %s.* TO 'foo'@'%s'", schema, this_host);
  rc= mysql_query(my, query);
  check_mysql_rc(rc, my);

  mysql= mysql_init(NULL);
  if (!my_test_connect(mysql, hostname, "foo", "foo", schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    return FAIL;
  }

  mysql_close(mysql);
  
  sprintf(query, "DROP USER 'foo'@'%s'", this_host);
  rc= mysql_query(my, query);
  check_mysql_rc(rc, mysql);

  return OK;
}

static int test_conc366(MYSQL *mysql)
{
  char query[1024];
  int rc;
  MYSQL *my;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
  {
    diag("feature not supported by MySQL server");
    return SKIP;
  }

  /* check if ed25519 plugin is available */
  if (!mysql_client_find_plugin(mysql, "client_ed25519", MYSQL_CLIENT_AUTHENTICATION_PLUGIN))
  {
    diag("client_ed25519 plugin not available");
    return SKIP;
  }

  rc= mysql_query(mysql, "INSTALL SONAME 'auth_ed25519'");
  if (rc)
  {
    diag("feature not supported, ed25519 plugin not available");
    return SKIP;
  }

  if (mysql_get_server_version(mysql) < 100400) {
    sprintf(query, "CREATE OR REPLACE USER 'ede'@'%s' IDENTIFIED VIA ed25519 USING '6aW9C7ENlasUfymtfMvMZZtnkCVlcb1ssxOLJ0kj/AA'", this_host);
  } else {
    sprintf(query, "CREATE OR REPLACE USER 'ede'@'%s' IDENTIFIED VIA ed25519 USING PASSWORD('MySup8%%rPassw@ord')", this_host);
  }
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);

  sprintf(query, "GRANT ALL ON %s.* TO 'ede'@'%s'", schema, this_host);
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);

  my= mysql_init(NULL);
  if (plugindir)
    mysql_options(my, MYSQL_PLUGIN_DIR, plugindir);
  if (!my_test_connect(my, hostname, "ede", "MySup8%rPassw@ord", schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(my));
    return FAIL;
  }
  mysql_close(my);

  sprintf(query, "DROP USER 'ede'@'%s'", this_host);
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);

  sprintf(query, "UNINSTALL SONAME 'auth_ed25519'");
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);
  return OK;
}

static int test_conc392(MYSQL *mysql)
{
  int rc;
  const char *data;
  size_t len;
  ulong capabilities= 0;

  SKIP_MYSQL(mysql);

  mariadb_get_infov(mysql, MARIADB_CONNECTION_SERVER_CAPABILITIES, &capabilities);
  if (!(capabilities & CLIENT_SESSION_TRACKING))
  {
    diag("Server doesn't support session tracking (cap=%lu)", mysql->server_capabilities);
    return SKIP;
  }
  
  rc= mysql_query(mysql, "set session_track_state_change=1");
  check_mysql_rc(rc, mysql);

  if (mysql_session_track_get_first(mysql, SESSION_TRACK_STATE_CHANGE, &data, &len))
  {
    diag("session_track_get_first failed");
    return FAIL;
  }
  
  FAIL_IF(len != 1, "Expected length 1");
  return OK;
}

static int test_conc443(MYSQL *my __attribute__((unused)))
{
  my_bool x= 1;
  unsigned long thread_id= 0;
  char query[128];
  MYSQL_RES *result;
  MYSQL_ROW row;
  int rc;

  MYSQL *mysql= mysql_init(NULL);

  SKIP_MAXSCALE;

  mysql_options(mysql, MYSQL_INIT_COMMAND, "set @a:=3");
  mysql_options(mysql, MYSQL_OPT_RECONNECT, &x);

  if (!my_test_connect(mysql, hostname, username, password, schema, port, socketname, CLIENT_REMEMBER_OPTIONS, 1))
  {
    diag("Connection failed. Error: %s", mysql_error(mysql));
    mysql_close(mysql);
  }

  thread_id= mysql_thread_id(mysql);

  sprintf(query, "KILL %lu", thread_id);
  rc= mysql_query(mysql, query);

  sleep(3);

  rc= mysql_ping(mysql);
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "SELECT @a");
  check_mysql_rc(rc, mysql);

  FAIL_IF(mysql_thread_id(mysql) == thread_id, "Expected different thread id");

  result= mysql_store_result(mysql);
  if (!result)
    return FAIL;
  row= mysql_fetch_row(result);
  FAIL_IF(strcmp(row[0],"3"), "Wrong result");

  mysql_free_result(result);
  mysql_close(mysql);

  return OK;
}

static int test_default_auth(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql;

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!is_mariadb)
    return SKIP;

  mysql= mysql_init(NULL);
  mysql_options(mysql, MYSQL_DEFAULT_AUTH, "mysql_clear_password");

  if (!my_test_connect(mysql, hostname, username, password, schema, port, socketname, CLIENT_REMEMBER_OPTIONS, 1))
  {
    diag("Connection failed. Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }
  mysql_close(mysql);

  mysql= mysql_init(NULL);
  mysql_options(mysql, MYSQL_DEFAULT_AUTH, "caching_sha2_password");

  if (!my_test_connect(mysql, hostname, username, password, schema, port, socketname, CLIENT_REMEMBER_OPTIONS, 1))
  {
    diag("Connection failed. Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  
  }
  mysql_close(mysql);
  return OK;
}

static int test_gtid(MYSQL *mysql)
{
  int rc;
  const char *data;
  size_t len;

  if (is_mariadb)
    return SKIP;
  // https://jira.mariadb.org/browse/XPT-182
  SKIP_XPAND;

  rc= mysql_query(mysql, "SET @@session.session_track_state_change=1");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "SET @@session.session_track_gtids=OWN_GTID");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "BEGIN");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "DROP TABLE IF EXISTS t1");
  check_mysql_rc(rc, mysql);

  if (!mysql_session_track_get_first(mysql, SESSION_TRACK_GTIDS, &data, &len))
  do {
    printf("# SESSION_TRACK_GTIDS: %*.*s\n", (int)len, (int)len, data);
  } while (!mysql_session_track_get_next(mysql, SESSION_TRACK_GTIDS, &data, &len));

  rc= mysql_query(mysql, "CREATE TABLE t1 (a int)");
  check_mysql_rc(rc, mysql);

  if (!mysql_session_track_get_first(mysql, SESSION_TRACK_GTIDS, &data, &len))
  do {
    printf("# SESSION_TRACK_GTIDS: %*.*s\n", (int)len, (int)len, data);
  } while (!mysql_session_track_get_next(mysql, SESSION_TRACK_GTIDS, &data, &len));

  rc= mysql_query(mysql, "COMMIT");
  check_mysql_rc(rc, mysql);

  return OK;
}

static int test_conc490(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);

  if (!my_test_connect(mysql, hostname, username,
                             password, NULL, port, socketname, CLIENT_CONNECT_WITH_DB, 1))
  {
    diag("error: %s\n", mysql_error(mysql));
    return FAIL;
  }
  mysql_close(mysql);
  return OK;
}

static int test_conc544(MYSQL *mysql)
{
  int rc;
  MYSQL *my= mysql_init(NULL);
  char query[1024];

  SKIP_SKYSQL;
  SKIP_MAXSCALE;

  if (!mysql_client_find_plugin(mysql, "client_ed25519", MYSQL_CLIENT_AUTHENTICATION_PLUGIN))
  {
    diag("client_ed25519 plugin not available");
    return SKIP;
  }

  rc= mysql_query(mysql, "INSTALL SONAME 'auth_ed25519'");
  if (rc)
  {
    diag("feature not supported, ed25519 plugin not available");
    return SKIP;
  }

  rc= mysql_optionsv(my, MARIADB_OPT_RESTRICTED_AUTH, "client_ed25519");
  check_mysql_rc(rc, mysql);

  if (my_test_connect(my, hostname, username,
                             password, schema, port, socketname, 0, 1))
  {
    diag("error expected (restricted auth)");
    return FAIL;
  }
  mysql_close(my);

  if (mysql_get_server_version(mysql) < 100400) {
    sprintf(query, "CREATE OR REPLACE USER 'ede'@'%s' IDENTIFIED VIA ed25519 USING '6aW9C7ENlasUfymtfMvMZZtnkCVlcb1ssxOLJ0kj/AA'", this_host);
  } else {
    sprintf(query, "CREATE OR REPLACE USER 'ede'@'%s' IDENTIFIED VIA ed25519 USING PASSWORD('MySup8%%rPassw@ord')", this_host);
  }
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);

  sprintf(query, "GRANT ALL ON %s.* TO 'ede'@'%s'", schema, this_host);
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);

  my= mysql_init(NULL);
  if (plugindir)
    mysql_optionsv(my, MYSQL_PLUGIN_DIR, plugindir);
  mysql_optionsv(my, MARIADB_OPT_RESTRICTED_AUTH, "client_ed25519, mysql_native_password");
  if (!my_test_connect(my, hostname, "ede", "MySup8%rPassw@ord", schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(my));
    return FAIL;
  }
  mysql_close(my);

  sprintf(query, "DROP USER 'ede'@'%s'", this_host);
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);

  sprintf(query, "UNINSTALL SONAME 'auth_ed25519'");
  rc= mysql_query(mysql, query);
  check_mysql_rc(rc, mysql);

  return OK;
}

static int test_conn_str(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);
  char conn_str[1024];
  int rc=OK;

  snprintf(conn_str, sizeof(conn_str)-1, "host=%s;user=%s;password={%s};port=%d;socket=%s;tls_fp=%s",
                hostname ? hostname : "localhost", username ? username : "", 
                password ? password : "", 
                port, socketname ? socketname : "",
                fingerprint[0] ? fingerprint : "");

  /* SkySQL requires secure connection */
  if (IS_SKYSQL(hostname))
  {
    strcat(conn_str, ";ssl_enforce=1");
  }

  if (mariadb_connect(mysql, conn_str))
  {
    diag("host: %s", mysql->host);
    diag("user: %s", mysql->user);
    diag("cipher: %s", mysql_get_ssl_cipher(mysql));
  } else
  {
    diag("error: %s", mysql_error(mysql));
    rc= FAIL;
  }
  mysql_close(mysql);
  return rc;
}

static int test_conn_str_1(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql;
  FILE *fp;
  int rc;
  char conn_str[1024];
  mysql= mysql_init(NULL);

  if (!(fp= fopen("./conc274.cnf", "w")))
    return FAIL;

  sprintf(conn_str, "connection=host=%s;user=%s;password={%s};port=%d;ssl_enforce=1;socket=%s",
                hostname ? hostname : "localhost", username ? username : "", 
                password ? password : "", ssl_port, socketname ? socketname : "");

  fprintf(fp, "[client]\n");
  fprintf(fp, "%s\n", conn_str);

  fclose(fp);

  rc= mysql_options(mysql, MYSQL_READ_DEFAULT_FILE, "./conc274.cnf");
  check_mysql_rc(rc, mysql);
  rc= mysql_options(mysql, MYSQL_READ_DEFAULT_GROUP, "");
  check_mysql_rc(rc, mysql);

  if (!my_test_connect(mysql, NULL, NULL, NULL, NULL, 0, NULL, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    remove("./conc274.cnf");
    return FAIL;
  }
  remove("./conc274.cnf");

  if (!mysql_get_ssl_cipher(mysql))
  {
    diag("Error: No TLS connection");
    return FAIL;
  }
  diag("Cipher in use: %s", mysql_get_ssl_cipher(mysql));
  mysql_close(mysql);
  return OK;
}

static int test_conc365(MYSQL *my __attribute__((unused)))
{
  int rc= OK;
  MYSQL *mysql= mysql_init(NULL);
  char tmp[1024];

  snprintf(tmp, sizeof(tmp) - 1,
   "host=127.0.0.1:3300,%s;user=%s;password={%s};port=%d;socket=%s;tls_fp=%s",
   hostname ? hostname : "localhost", username ? username : "", password ? password : "",
   port, socketname ? socketname : "", fingerprint[0] ? fingerprint : "");

 if (IS_SKYSQL(hostname))
   strcat(tmp, ";ssl_enforce=1");

 if (!mariadb_connect(mysql, tmp))
   rc= FAIL;

  mysql_close(mysql);

  if (rc)
    return rc;

  mysql= mysql_init(NULL);
  snprintf(tmp, sizeof(tmp) -1, "127.0.0.1:3300,%s:%d", hostname ? hostname : "localhost", port);
  if (!my_test_connect(mysql, tmp, username,
                             password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    rc= FAIL;
  }

  mysql_close(mysql);

  if (rc)
    return rc;
  
  mysql= mysql_init(NULL);
  mysql_options(mysql, MARIADB_OPT_HOST, tmp);
  if (!my_test_connect(mysql, NULL, username,
                             password, schema, port, socketname, 0, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    rc= FAIL;
  }

  mysql_close(mysql);
  return rc;
}

static int test_conc365_reconnect(MYSQL *my)
{
  int rc= OK;
  MYSQL *mysql= mysql_init(NULL);
  char tmp[1024];
  my_bool reconnect= 1;

  SKIP_MAXSCALE;

  mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect);

  if (IS_SKYSQL(hostname))
  {
    snprintf(tmp, sizeof(tmp) - 1,
      "host=127.0.0.1:3300,%s;user=%s;password={%s};port=%d;socket=%s;ssl_enforce=1;tls_fp=%s",
      hostname ? hostname : "localhost", username ? username : "", password ? password : "",
      ssl_port, socketname ? socketname : "", fingerprint[0] ? fingerprint : "");
  } else {
    snprintf(tmp, sizeof(tmp) - 1,
      "host=127.0.0.1:3300,%s;user=%s;password={%s};port=%d;socket=%s;tls_fp=%s",
      hostname ? hostname : "localhost", username ? username : "", password ? password : "",
      port, socketname ? socketname : "", fingerprint[0] ? fingerprint :"");
  }

  if (!my_test_connect(mysql, tmp, username,
                             password, schema, port, socketname, CLIENT_REMEMBER_OPTIONS, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    rc= FAIL;
  }

  sprintf(tmp, "KILL %ld", mysql_thread_id(mysql));
  diag("KILL %ld", mysql_thread_id(mysql));

  rc= mysql_query(my, tmp);
  check_mysql_rc(rc, my);

  sleep(3);
  rc= mysql_ping(mysql);
  check_mysql_rc(rc, my);

  mysql_close(mysql);
  return rc;
}

struct st_callback {
  char autocommit;
  char database[64];
  char charset[64];
};

void my_status_callback(void *ptr, enum enum_mariadb_status_info type, ...)
{
  va_list ap;
  struct st_callback *data= (struct st_callback *)ptr;
  va_start(ap, type);

  switch(type) {
  case STATUS_TYPE:
    {
      int status= va_arg(ap, int);
      data->autocommit= status & SERVER_STATUS_AUTOCOMMIT;
    }
    break;
  case SESSION_TRACK_TYPE:
    {
      enum enum_session_state_type track_type= va_arg(ap, enum enum_session_state_type);
      switch (track_type) {
      case SESSION_TRACK_SCHEMA:
        {
          MARIADB_CONST_STRING *str= va_arg(ap, MARIADB_CONST_STRING *);
          strncpy(data->database, str->str, str->length);
          data->database[str->length]= 0;
        }
        break;
      case SESSION_TRACK_SYSTEM_VARIABLES:
        {
          MARIADB_CONST_STRING *key= va_arg(ap, MARIADB_CONST_STRING *);
          MARIADB_CONST_STRING *val= va_arg(ap, MARIADB_CONST_STRING *);

          if (!strncmp(key->str, "character_set_client", key->length))
          {
            strncpy(data->charset, val->str, val->length);
            data->charset[val->length]= 0;
          }
        }
        break;
      default:
        break;
      }
    }
  default:
    break;
  }
  va_end(ap);
}

static int test_status_callback(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);
  char tmp[64];
  int rc;
  struct st_callback data= {0,"", ""};

  rc= mysql_optionsv(mysql, MARIADB_OPT_STATUS_CALLBACK, my_status_callback, &data);

  if (!my_test_connect(mysql, hostname, username,
                      password, NULL, port, socketname, 0, 1))
  {
    diag("error1: %s", mysql_error(mysql));
    return FAIL;
  }

  rc= mysql_autocommit(mysql, 0);
  check_mysql_rc(rc, mysql);
  rc= mysql_autocommit(mysql, 1);
  check_mysql_rc(rc, mysql);

  if (!data.autocommit)
  {
    diag("autocommit not set");
    return FAIL;
  }
  diag("-------------------------");

  sprintf(tmp, "USE %s", schema);
  rc= mysql_query(mysql, tmp);
  check_mysql_rc(rc, mysql);

  if (strcmp(data.database, schema))
  {
    diag("Expected database: %s instead of %s", schema, data.database);
    return FAIL;
  }

  rc= mysql_query(mysql, "SET NAMES latin1");
  check_mysql_rc(rc, mysql);

  if (strcmp(data.charset, "latin1"))
  {
    diag("Expected charset latin1 instead of %s", data.charset);
    return FAIL;
  }

  mysql_close(mysql);
  return OK;
}

static int test_conc632(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);
  int rc;

  if (!my_test_connect(mysql, hostname, username, password, schema, port, socketname, CLIENT_REMEMBER_OPTIONS, 1))
  {
    diag("Connection failed. Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  rc= mysql_query(mysql, "DROP PROCEDURE conc632");

  rc= mysql_query(mysql, "CREATE PROCEDURE conc632() "
                         "BEGIN "
                         "  SELECT 1;"
                         "  SELECT 2;"
                         "END");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "CALL conc632()");
  check_mysql_rc(rc, mysql);

  rc= mysql_reset_connection(mysql);
  check_mysql_rc(rc, mysql);

  rc= mysql_ping(mysql);
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "DROP PROCEDURE conc632");
  check_mysql_rc(rc, mysql);

  mysql_close(mysql);
  return OK;
}

static int test_conc505(MYSQL *my __attribute__((unused)))
{
  MYSQL *mysql= mysql_init(NULL);

#define CLIENT_DEPRECATE_EOF (1ULL << 24)

  if (my_test_connect(mysql, hostname, username, password, schema, port, socketname, CLIENT_DEPRECATE_EOF, 1))
  {
    diag("Error expected: Invalid client flag");
    mysql_close(mysql);
    return FAIL;
  }
  diag("Error (expected): %s", mysql_error(mysql));
  FAIL_IF(mysql_errno(mysql) != CR_INVALID_CLIENT_FLAG, "Wrong error number");
  if (!my_test_connect(mysql, hostname, username, password, schema, port, socketname, CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS, 1))
  {
    diag("Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  mysql_close(mysql);
  return OK;
}

static int test_parsec(MYSQL *my)
{
  int rc;
  int verify= 0;
  MYSQL *mysql;
  rc= mysql_query(my, "INSTALL soname 'auth_parsec'");
  if (rc)
  {
    diag("server doesn't support parsec plugin");
    return SKIP;
  }
  rc= mysql_query(my, "CREATE OR REPLACE USER test1@'%' IDENTIFIED VIA parsec using PASSWORD('123')");
  check_mysql_rc(rc, my);

  mysql= mysql_init(NULL);
  if (!mysql_client_find_plugin(mysql, "parsec", MYSQL_CLIENT_AUTHENTICATION_PLUGIN))
  {
    diag("parsec plugin not available");
    diag("error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return SKIP;
  }

  mysql_options(mysql, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &verify);
  if (!my_test_connect(mysql, hostname, "test1", "123", NULL, port, socketname, 0, 0))
  {
    diag("Connection failed. Error: %s", mysql_error(mysql));
    mysql_close(mysql);
    return FAIL;
  }

  rc= mysql_query(my, "DROP USER test1@'%'");
  check_mysql_rc(rc, my);

  mysql_close(mysql);
  return OK;
}

/* Test for PR250 */
int test_tls_timeout(MYSQL *unused __attribute__((unused)))
{
  unsigned int connect_timeout= 5;
  unsigned int read_write_timeout= 10;
  int rc;
  time_t start, elapsed;

  MYSQL *mysql= mysql_init(NULL);
  mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
  mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (unsigned int *)&connect_timeout);
  mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT, (unsigned int *)&read_write_timeout);
  mysql_options(mysql, MYSQL_OPT_WRITE_TIMEOUT, (unsigned int *)&read_write_timeout);
  if (!my_test_connect(mysql, hostname, username, password, schema, port, socketname, CLIENT_REMEMBER_OPTIONS, 1))
  {
    mysql_close(mysql);
    return FAIL;
  }

  start= time(NULL);
  rc= mysql_query(mysql, "SET @a:=SLEEP(12)");
  elapsed= time(NULL) - start;
  diag("elapsed: %lu", (unsigned long)elapsed);
  FAIL_IF((unsigned int)elapsed > read_write_timeout + 1, "timeout ignored");

  FAIL_IF(!rc, "expected timeout error");
  diag("Error: %s", mysql_error(mysql));

  mysql_close(mysql);
  return OK;
}


struct my_tests_st my_tests[] = {
  {"test_tls_timeout", test_tls_timeout, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_parsec", test_parsec, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_conc505", test_conc505, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_conc632", test_conc632, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_status_callback", test_status_callback, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_conc365", test_conc365, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_conc365_reconnect", test_conc365_reconnect, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_conn_str", test_conn_str, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_conn_str_1", test_conn_str_1, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_conc544", test_conc544, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_conc490", test_conc490, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_gtid", test_gtid, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_conc496", test_conc496, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_default_auth", test_default_auth, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_conc443", test_conc443, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_conc366", test_conc366, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_conc392", test_conc392, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_conc312", test_conc312, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_conc351", test_conc351, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_conc332", test_conc332, TEST_CONNECTION_NONE, 0, NULL, NULL},
#ifndef WIN32
  {"test_conc327", test_conc327, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_conc317", test_conc317, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
#endif
  {"test_conc315", test_conc315, TEST_CONNECTION_NEW, 0, NULL,  NULL},
  {"test_expired_pw", test_expired_pw, TEST_CONNECTION_DEFAULT, 0, NULL,  NULL},
  {"test_conc276", test_conc276, TEST_CONNECTION_NONE, 0, NULL,  NULL},
  {"test_mdev13100", test_mdev13100, TEST_CONNECTION_DEFAULT, 0, NULL,  NULL},
  {"test_auth256", test_auth256, TEST_CONNECTION_DEFAULT, 0, NULL,  NULL},
  {"test_reset", test_reset, TEST_CONNECTION_DEFAULT, 0, NULL,  NULL},
  {"test_unix_socket_close", test_unix_socket_close, TEST_CONNECTION_NONE, 0, NULL,  NULL},
  {"test_sess_track_db", test_sess_track_db, TEST_CONNECTION_DEFAULT, 0, NULL,  NULL},
  {"test_get_options", test_get_options, TEST_CONNECTION_DEFAULT, 0, NULL,  NULL},
  {"test_wrong_bind_address", test_wrong_bind_address, TEST_CONNECTION_DEFAULT, 0, NULL,  NULL},
  {"test_bind_address", test_bind_address, TEST_CONNECTION_DEFAULT, 0, NULL,  NULL},
  {"test_conc118", test_conc118, TEST_CONNECTION_DEFAULT, 0, NULL,  NULL},
  {"test_conc66", test_conc66, TEST_CONNECTION_DEFAULT, 0, NULL,  NULL},
  {"test_bug20023", test_bug20023, TEST_CONNECTION_NEW, 0, NULL,  NULL},
  {"test_bug31669", test_bug31669, TEST_CONNECTION_NEW, 0, NULL,  NULL},
  {"test_bug33831", test_bug33831, TEST_CONNECTION_NEW, 0, NULL,  NULL},
  {"test_change_user", test_change_user, TEST_CONNECTION_NEW, 0, NULL,  NULL},
  {"test_opt_reconnect", test_opt_reconnect, TEST_CONNECTION_NONE, 0, NULL,  NULL},
  {"test_compress", test_compress, TEST_CONNECTION_NONE, 0, NULL,  NULL},
  {"test_reconnect", test_reconnect, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_conc21", test_conc21, TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_conc26", test_conc26, TEST_CONNECTION_NONE, 0, NULL, NULL}, 
  {"test_connection_timeout", test_connection_timeout, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_connection_timeout2", test_connection_timeout2, TEST_CONNECTION_NONE, 0, NULL, NULL}, 
  {"test_connection_timeout3", test_connection_timeout3, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {"test_tls_timeout", test_tls_timeout, TEST_CONNECTION_NONE, 0, NULL, NULL},
  {NULL, NULL, 0, 0, NULL, NULL}
};


int main(int argc, char **argv)
{
  if (argc > 1)
    get_options(argc, argv);

  get_envvars();

  run_tests(my_tests);

  return(exit_status());
}
