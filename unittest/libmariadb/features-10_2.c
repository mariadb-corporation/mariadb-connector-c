/*
*/

#include "my_test.h"

static int com_multi_1(MYSQL *mysql)
{
  int rc;
  my_bool is_multi= 1;

  if (mysql_options(mysql, MARIADB_OPT_COM_MULTI, &is_multi))
  {
    diag("COM_MULT not supported");
    return SKIP;
  }

  rc= mysql_query(mysql, "SET @a:=1");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "SET @b:=2");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "select @a,@b");
  check_mysql_rc(rc, mysql);

  rc= mariadb_flush_multi_command(mysql);
  check_mysql_rc(rc, mysql);

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
