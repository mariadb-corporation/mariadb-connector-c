/*
*/

#include "my_test.h"

static int com_multi_1(MYSQL *mysql)
{
  int rc;
  MYSQL_RES *res;
  my_bool is_multi= 1;

  /* TEST a simple query before COM_MULTI */

  rc= mysql_query(mysql, "select 1");
  check_mysql_rc(rc, mysql);
  FAIL_UNLESS(res, "1 simple query no result");
  res= mysql_store_result(mysql);

  mysql_free_result(res);

  /* TEST COM_MULTI */

  if (mysql_options(mysql, MARIADB_OPT_COM_MULTI, &is_multi))
  {
    diag("COM_MULT not supported");
    return SKIP;
  }

  rc= mysql_query(mysql, "select 1");

  rc= mysql_query(mysql, "select 2");

  rc= mariadb_flush_multi_command(mysql);
  check_mysql_rc(rc, mysql);
  /* 1 SELECT result */
  res= mysql_store_result(mysql);
  FAIL_UNLESS(res, "1 of 2 simple query in batch no result");
  mysql_free_result(res);
  /* 2 SELECT result */
  rc= mysql_next_result(mysql);
  FAIL_UNLESS(rc == 0, "no second result in the batch");
  res= mysql_store_result(mysql);
  FAIL_UNLESS(res, "2 of 2 simple query in batch no result");
  mysql_free_result(res);
  /* WHOLE batch result (OK) */
  rc= mysql_next_result(mysql);
  res= mysql_store_result(mysql);
  FAIL_UNLESS(res == NULL, "rows instead of batch OK");
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

struct my_tests_st my_tests[] = {
  {"com_multi_1", com_multi_1, TEST_CONNECTION_NEW, 0,  NULL,  NULL},
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
