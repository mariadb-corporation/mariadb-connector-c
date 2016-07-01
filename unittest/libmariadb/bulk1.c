/*
  Copyright 2011 Kristian Nielsen and Monty Program Ab.

  This file is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "my_test.h"
#include "ma_common.h"

#define TEST_ARRAY_SIZE 1024

char *rand_str(size_t length) {
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char *dest= (char *)malloc(length+1);
    char *p= dest;
    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
    return p;
}

static int bulk1(MYSQL *mysql)
{
  MYSQL_STMT *stmt= mysql_stmt_init(mysql);
  char *stmt_str= "INSERT INTO bulk1 VALUES (?,?)";
  unsigned long array_size= TEST_ARRAY_SIZE;
  int rc;
  int i;
  char **buffer;
  unsigned long *lengths;
  unsigned int *vals;
  MYSQL_BIND bind[2];
  MYSQL_RES *res;
  MYSQL_ROW row;
  int intval;

  rc= mysql_query(mysql, "DROP TABLE IF EXISTS bulk1");
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "CREATE TABLE bulk1 (a int, b VARCHAR(255))");
  check_mysql_rc(rc, mysql);

  rc= mysql_stmt_prepare(stmt, stmt_str, strlen(stmt_str));
  check_stmt_rc(rc, stmt);

  /* allocate memory */
  buffer= calloc(TEST_ARRAY_SIZE, sizeof(char *));
  lengths= (unsigned long *)calloc(sizeof(long), TEST_ARRAY_SIZE);
  vals= (int *)calloc(sizeof(int), TEST_ARRAY_SIZE);

  for (i=0; i < TEST_ARRAY_SIZE; i++)
  {
    buffer[i]= rand_str(254);
    lengths[i]= -1;
    vals[i]= i; 
  }

  memset(bind, 0, sizeof(MYSQL_BIND) * 2);
  bind[0].buffer_type= MYSQL_TYPE_LONG;
  bind[0].buffer= (int *)&vals[0];
  bind[1].buffer_type= MYSQL_TYPE_STRING;
  bind[1].buffer= (void *)buffer;
  bind[1].length= (long *)lengths;

  rc= mysql_stmt_attr_set(stmt, STMT_ATTR_ARRAY_SIZE, &array_size);
  check_stmt_rc(rc, stmt);

  rc= mysql_stmt_bind_param(stmt, bind);
  check_stmt_rc(rc, stmt);

  for (i=0; i < 10; i++)
  {
    rc= mysql_stmt_execute(stmt);
    check_stmt_rc(rc, stmt);
    diag("Affected rows: %d", mysql_stmt_affected_rows(stmt));
  }

  for (i=0; i < array_size; i++)
    free(buffer[i]);

  free(buffer);
  free(lengths);
  free(vals);

  rc= mysql_stmt_close(stmt);
  check_mysql_rc(rc, mysql);

  rc= mysql_query(mysql, "SELECT COUNT(*) FROM bulk1");
  check_mysql_rc(rc, mysql);

  res= mysql_store_result(mysql);
  row= mysql_fetch_row(res);
  intval= atoi(row[0]);
  mysql_free_result(res);
  FAIL_IF(intval != array_size * 10, "Expected 10240 rows");

  rc= mysql_query(mysql, "SELECT MAX(a) FROM bulk1");
  check_mysql_rc(rc, mysql);

  res= mysql_store_result(mysql);
  row= mysql_fetch_row(res);
  intval= atoi(row[0]);
  mysql_free_result(res);
  FAIL_IF(intval != array_size - 1, "Expected max value 1024");

/*
  rc= mysql_query(mysql, "DROP TABLE IF EXISTS bulk1");
  check_mysql_rc(rc, mysql);
*/
  return OK;

}

struct my_tests_st my_tests[] = {
  {"bulk1", bulk1, TEST_CONNECTION_DEFAULT, 0,  NULL,  NULL},
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
