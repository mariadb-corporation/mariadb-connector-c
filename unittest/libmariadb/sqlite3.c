/**
  Some basic tests for sqlite
*/

#include "my_test.h"

#ifdef HAVE_SQLITE
static int test1(MYSQL *mysql)
{
  MYSQL_ROW row;
  MYSQL_RES *res;
  int rc;

  MYSQL *my= mysql_init(NULL);
  FAIL_IF(!my, "mysql_init() failed");

  mysql_options(my, MYSQL_DATABASE_DRIVER, "sqlite");

  FAIL_IF(!mysql_real_connect(my, hostname, username, password, (schema) ? schema : "test",
                         port, socketname, 0), mysql_error(my));

  diag("Server name: %s", mysql_get_server_name(my));

  diag("Connected to: %s (%lu)", mysql_get_server_info(my), mysql_get_server_version(my));

  rc= mysql_query(my, "CREATE TABLE t1 (a int, b varchar(255))");
  rc= mysql_query(my, "DELETE FROM t1");
  check_mysql_rc(rc, my);

  rc= mysql_query(my, "BEGIN");
  check_mysql_rc(rc, my);
  rc= mysql_query(my, "INSERT INTO t1 VALUES (1, 'Monty')");
  check_mysql_rc(rc, my);
  rc= mysql_query(my, "INSERT INTO t1 VALUES (2, 'Serg')");
  check_mysql_rc(rc, my);
  rc= mysql_query(my, "INSERT INTO t1 VALUES (3, 'Holyfoot')");
  check_mysql_rc(rc, my);
  rc= mysql_query(my, "INSERT INTO t1 VALUES (4, 'Rasmus')");
  check_mysql_rc(rc, my);
  rc= mysql_query(my, "INSERT INTO t1 VALUES (5, 'Sanja')");
  check_mysql_rc(rc, my);
  rc= mysql_query(my, "COMMIT");
  check_mysql_rc(rc, my);

  rc= mysql_query(my, "SELECT a,b FROM t1");
  check_mysql_rc(rc, my);
  res= mysql_use_result(my);
  FAIL_IF(!res, mysql_error(my));

  while ((row= mysql_fetch_row(res)) != NULL)
  {
    FAIL_IF(mysql_num_fields(res) != 2, "Got the wrong number of fields");
  }
  FAIL_IF(mysql_num_rows(res) != 5, "expected 5 rows");
  FAIL_IF(mysql_errno(my), mysql_error(my));

  mysql_free_result(res);

  rc= mysql_query(my, "SELECT a FROM t1");
  check_mysql_rc(rc, my);
  res= mysql_use_result(my);
  mysql_free_result(res);

  FAIL_IF(mysql_errno(my), mysql_error(my));

  mysql_close(my);

  return OK;
}

static int test_simple_prepare(MYSQL *my)
{
  MYSQL *mysql= mysql_init(NULL);
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[2];
  int val1= 17;
  char *val2= "MariaDB";
  char buffer[100];
  char *stmt_create= "CREATE TABLE t2 (a int, b varchar(200), c int)";
  char *stmt_insert= "INSERT INTO t2 VALUES (1, ?, ?)";
  int rc;

  FAIL_IF(!mysql, "mysql_init() failed");

  mysql_options(mysql, MYSQL_DATABASE_DRIVER, "sqlite");

  FAIL_IF(!mysql_real_connect(mysql, hostname, username, password, (schema) ? schema : "test",
                         port, socketname, 0), mysql_error(my));

  rc= mysql_query(mysql, "DROP TABLE IF EXISTS t2");
  check_mysql_rc(rc, mysql);

  stmt= mysql_stmt_init(mysql);
  rc= mysql_stmt_prepare(stmt, stmt_create, strlen(stmt_create));
  FAIL_IF(stmt->stmt_id != 1, "expected stmt_id=1");
  check_stmt_rc(rc, stmt);

  FAIL_IF(mysql_stmt_param_count(stmt), "Expected param_count= 0");

  rc= mysql_stmt_execute(stmt);
  check_stmt_rc(rc, stmt);
  mysql_stmt_close(stmt);

  stmt= mysql_stmt_init(mysql);
  rc= mysql_stmt_prepare(stmt, stmt_insert, strlen(stmt_insert));
  FAIL_IF(stmt->stmt_id != 2, "expected stmt_id=2");
  check_stmt_rc(rc, stmt);

  FAIL_IF(mysql_stmt_param_count(stmt) != 2, "Expected 2 parameters");

  mysql_stmt_close(stmt);

  stmt= mysql_stmt_init(mysql);
  rc= mysql_stmt_prepare(stmt, "CREATE xxxx (a int)", 50);
  FAIL_IF(rc == 0, "error expected");
  mysql_stmt_close(stmt);

  rc= mysql_query(mysql, "DROP TABLE IF EXISTS t2");
  check_mysql_rc(rc, mysql);
  rc= mysql_query(mysql, "CREATE TABLE t2 (a int, b varchar(20))");
  check_mysql_rc(rc, mysql);

  stmt= mysql_stmt_init(mysql);
  rc= mysql_stmt_prepare(stmt, "INSERT INTO t2 VALUES(?,?)", 50);
  check_stmt_rc(rc, stmt);

  memset(bind, 0, sizeof(MYSQL_BIND) * 2);
  bind[0].buffer_type= MYSQL_TYPE_LONG;
  bind[0].buffer= &val1;

  bind[1].buffer_type= MYSQL_TYPE_STRING;
  bind[1].buffer= val2;
  bind[1].buffer_length= strlen(val2);

  rc= mysql_stmt_bind_param(stmt, bind);
  check_stmt_rc(rc, stmt);

  rc= mysql_stmt_execute(stmt);
  check_stmt_rc(rc, stmt);

  val1++;

  rc= mysql_stmt_execute(stmt);
  check_stmt_rc(rc, stmt);
  mysql_stmt_close(stmt);

  bind[1].buffer= buffer;

  stmt= mysql_stmt_init(mysql);
  rc= mysql_stmt_prepare(stmt, "SELECT a,b FROM t2", 50);
  check_stmt_rc(rc, stmt);

  rc= mysql_stmt_execute(stmt);
  check_stmt_rc(rc, stmt);
  rc= mysql_stmt_bind_result(stmt, bind);
  check_stmt_rc(rc, stmt);


  mysql_stmt_fetch(stmt);
  FAIL_IF(val1 != 17, "expected value=17");

  mysql_stmt_fetch(stmt);
  FAIL_IF(val1 != 18, "expected value=18");

  rc= mysql_stmt_fetch(stmt);
  FAIL_IF(rc != MYSQL_NO_DATA, "Expected eof");
  mysql_stmt_close(stmt);
  mysql_close(mysql);

  return OK;
}
#endif


struct my_tests_st my_tests[] = {
#ifdef HAVE_SQLITE
  {"test-sqlite", test1, TEST_CONNECTION_NONE, 0,  NULL,  NULL},
  {"test_simple_prepare", test_simple_prepare, TEST_CONNECTION_NONE, 0, NULL, NULL},
#endif
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
