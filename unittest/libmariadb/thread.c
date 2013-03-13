/*
*/

#include "my_test.h"

static int basic_connect(MYSQL *mysql)
{
  MYSQL_ROW row;
  MYSQL_RES *res;
  MYSQL_FIELD *field;
  int rc;

  MYSQL *my= mysql_init(NULL);
  FAIL_IF(!my, "mysql_init() failed");

  FAIL_IF(!mysql_real_connect(my, hostname, username, password, schema,
                         port, socketname, 0), mysql_error(my));

  rc= mysql_query(my, "SELECT @@version");
  check_mysql_rc(rc, my);

  res= mysql_store_result(my);
  FAIL_IF(!res, mysql_error(my));
  field= mysql_fetch_fields(res);
  FAIL_IF(!field, "Couldn't fetch fields");

  while ((row= mysql_fetch_row(res)) != NULL)
  {
    FAIL_IF(mysql_num_fields(res) != 1, "Got the wrong number of fields");
  }
  FAIL_IF(mysql_errno(my), mysql_error(my));

  mysql_free_result(res);
  mysql_close(my);

  return OK;
}

struct my_tests_st my_tests[] = {
  {"basic_connect", basic_connect, TEST_CONNECTION_NONE, 0,  NULL,  NULL},
  {NULL, NULL, 0, 0, NULL, NULL}
};


int main(int argc, char **argv)
{

  mysql_library_init(0,0,NULL);
  mysql_thread_init();
  mysql_thread_end();
  mysql_library_end();

  if (argc > 1)
    get_options(argc, argv);

  get_envvars();

  run_tests(my_tests);

  return(exit_status());
}
