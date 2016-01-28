/*
*/

#include "my_test.h"

my_bool have_com_multi= 1;

static int com_multi_1(MYSQL *mysql)
{
  int rc;
  MYSQL_RES *res;
  enum mariadb_com_multi status;

  /* TEST a simple query before COM_MULTI */

  rc= mysql_query(mysql, "select 1");
  check_mysql_rc(rc, mysql);
  res= mysql_store_result(mysql);
  FAIL_UNLESS(res, "1 simple query no result");

  mysql_free_result(res);

  /* TEST COM_MULTI */

  status= MARIADB_COM_MULTI_BEGIN;
  if (mysql_options(mysql, MARIADB_OPT_COM_MULTI, &status))
  {
    diag("COM_MULT not supported");
    have_com_multi= 0;
    return SKIP;
  }

  rc= mysql_query(mysql, "select 1");

  rc= mysql_query(mysql, "select 2");

  status= MARIADB_COM_MULTI_END;
  rc= mysql_options(mysql, MARIADB_OPT_COM_MULTI, &status);
  check_mysql_rc(rc, mysql);
  /* 1 SELECT result */
  res= mysql_store_result(mysql);
  FAIL_UNLESS(res, "1 of 2 simple query in batch no result");
  FAIL_UNLESS(res->field_count == 1 && res->row_count == 1 &&
              strcmp(res->fields[0].name, "1") == 0,
              "1 of 2 simple query in batch wrong result");
  mysql_free_result(res);
  /* 2 SELECT result */
  rc= mysql_next_result(mysql);
  FAIL_UNLESS(rc == 0, "no second result in the batch");
  res= mysql_store_result(mysql);
  FAIL_UNLESS(res, "2 of 2 simple query in batch no result");
  FAIL_UNLESS(res->field_count == 1 && res->row_count == 1 &&
              strcmp(res->fields[0].name, "2") == 0,
              "1 of 2 simple query in batch wrong result");
  mysql_free_result(res);
  rc= mysql_next_result(mysql);
  FAIL_UNLESS(rc == -1, "more then 2 results");

  /* TEST a simple query after COM_MULTI */

  rc= mysql_query(mysql, "select 1");
  check_mysql_rc(rc, mysql);
  res= mysql_store_result(mysql);
  FAIL_UNLESS(res, "2 simple query no result");
  mysql_free_result(res);

  /* question: how will result sets look like ? */
  diag("error: %s", mysql_error(mysql));

  return OK;
}

static int com_multi_ps1(MYSQL *mysql)
{
  MYSQL_STMT *stmt= mysql_stmt_init(mysql);
  int rc;

  if (!have_com_multi)
    return SKIP;

  rc= mysql_query(mysql, "DROP TABLE IF EXISTS t1");
  check_mysql_rc(rc, mysql);
  rc= mysql_query(mysql, "CREATE TABLE t1 (a int, b varchar(20))");

  rc= mysql_stmt_prepare(stmt, "INSERT INTO t1 values (2, 'execute_direct')", -1);
  check_stmt_rc(rc, stmt);

  rc= mysql_stmt_execute(stmt);
  check_stmt_rc(rc, stmt);
  diag("affected_rows: %d", mysql_stmt_affected_rows(stmt));
  diag("stmt_id: %d", stmt->stmt_id);
  mysql_stmt_close(stmt);

  stmt= mysql_stmt_init(mysql);
  rc= mariadb_stmt_execute_direct(stmt, "INSERT INTO t1 values (2, 'execute_direct')", -1);
  check_stmt_rc(rc, stmt);

  FAIL_IF(mysql_stmt_affected_rows(stmt) != 1, "expected affected_rows= 1");
  FAIL_IF(stmt->stmt_id < 1, "expected statement id > 0");

  rc= mysql_stmt_close(stmt);
  check_mysql_rc(rc, mysql);

  return OK;
}

static int com_multi_ps2(MYSQL *mysql)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND bind[3];
  int intval= 3, rc;
  int i;
  char *varval= "com_multi_ps2";


  if (!have_com_multi)
    return SKIP;

  rc= mysql_query(mysql, "DROP TABLE IF EXISTS t1");
  check_mysql_rc(rc, mysql);
  rc= mysql_query(mysql, "CREATE TABLE t1 (a int, b varchar(20))");

  memset(&bind, 0, sizeof(MYSQL_BIND) * 3);
  bind[0].buffer_type= MYSQL_TYPE_SHORT;
  bind[0].buffer= &intval;
  bind[1].buffer_type= MYSQL_TYPE_STRING;
  bind[1].buffer= varval;
  bind[1].buffer_length= strlen(varval);
  bind[2].buffer_type= MAX_NO_FIELD_TYPES;

  for (i=0; i < 2; i++)
  {
    stmt= mysql_stmt_init(mysql);
    rc= mysql_stmt_bind_param(stmt, bind);
    check_stmt_rc(rc, stmt);

    rc= mariadb_stmt_execute_direct(stmt, "INSERT INTO t1 VALUES (1,'foo')", -1);
    check_stmt_rc(rc, stmt);
    FAIL_IF(mysql_stmt_affected_rows(stmt) != 1, "expected affected_rows= 1");
    FAIL_IF(stmt->stmt_id < 1, "expected statement id > 0");

    rc= mysql_stmt_close(stmt);
    check_mysql_rc(rc, mysql);
  }

  return OK;
}

struct my_tests_st my_tests[] = {
  {"com_multi_1", com_multi_1, TEST_CONNECTION_NEW, 0,  NULL,  NULL},
  {"com_multi_ps1", com_multi_ps1, TEST_CONNECTION_NEW, 0,  NULL,  NULL},
  {"com_multi_ps2", com_multi_ps2, TEST_CONNECTION_NEW, 0,  NULL,  NULL},
  {NULL, NULL, 0, 0, NULL, NULL}
};


int main(int argc, char **argv)
{

  mysql_library_init(0,0,NULL);

  if (argc > 1)
    get_options(argc, argv);

  get_envvars();

  run_tests(my_tests);

  mysql_server_end();
  return(exit_status());
}
