/*
  MDEV-33387 client-library test for multi-factor authentication.

  Verifies that libmariadb's AuthNextFactor (0x02) handling and
  MYSQL_OPT_USER_PASSWORD option work against both MariaDB and MySQL.

  Requires the qa_auth_interface test plugin on the server (ships with
  both MariaDB and MySQL). The matching client-side plugin must be in
  the client plugin directory.

  Usage:
    set MYSQL_TEST_HOST=127.0.0.1
    set MYSQL_TEST_PORT=3306
    set MYSQL_TEST_USER=root
    set MYSQL_TEST_PASSWD=<root pw>
    set MYSQL_TEST_PLUGINDIR=<path to client plugins>
    mfa-t.exe

  Requires the connecting user to have CREATE USER / DROP USER / SUPER
  (to INSTALL PLUGIN) / GRANT PROXY.
*/

#include "my_test.h"

#ifdef _WIN32
#define PLUGIN_EXT ".dll"
#else
#define PLUGIN_EXT ".so"
#endif

static const char *mfa_user= "qa_test_1_user";
static const char *proxy_user= "qa_test_1_dest";

static void drop_users(MYSQL *conn)
{
  char buf[256];
  snprintf(buf, sizeof(buf), "DROP USER IF EXISTS '%s', '%s'",
           mfa_user, proxy_user);
  mysql_query(conn, buf);
}

/*
  Check server supports MFA: MariaDB >= 13.1 or MySQL >= 8.0.27.
  Returns 1 if supported, 0 otherwise.
*/
static int check_mfa_support(MYSQL *conn)
{
  MYSQL_RES *res;
  MYSQL_ROW row;
  int rc;
  unsigned int major= 0, minor= 0, patch= 0;

  rc= mysql_query(conn, "SELECT @@version");
  if (rc)
    return 0;
  res= mysql_store_result(conn);
  if (!res)
    return 0;
  row= mysql_fetch_row(res);
  if (!row || !row[0])
  {
    mysql_free_result(res);
    return 0;
  }
  sscanf(row[0], "%u.%u.%u", &major, &minor, &patch);
  diag("Server version: %s (parsed %u.%u.%u)", row[0], major, minor, patch);
  mysql_free_result(res);

  if (mariadb_connection(conn))
  {
    if (major > 13 || (major == 13 && minor >= 1))
      return 1;
    diag("MariaDB < 13.1, MFA not supported");
    return 0;
  }

  /* MySQL */
  if (major > 8 || (major == 8 && (minor > 0 || patch >= 27)))
    return 1;
  diag("MySQL < 8.0.27, MFA not supported");
  return 0;
}

/*
  Load qa_auth_interface server plugin if not already active.
  Returns 1 if the plugin is available, 0 otherwise.
*/
static int ensure_qa_plugin(MYSQL *conn)
{
  MYSQL_RES *res;
  int rc, present= 0;

  rc= mysql_query(conn,
    "SELECT 1 FROM information_schema.plugins "
    "WHERE plugin_name='qa_auth_interface' AND plugin_status='ACTIVE'");
  if (rc == 0 && (res= mysql_store_result(conn)))
  {
    present= (mysql_num_rows(res) > 0);
    mysql_free_result(res);
  }
  if (present) return 1;

  rc= mysql_query(conn, "INSTALL PLUGIN qa_auth_interface"
                         " SONAME 'qa_auth_interface" PLUGIN_EXT "'");
  if (rc)
  {
    diag("qa_auth_interface not installable: %s", mysql_error(conn));
    return 0;
  }
  return 1;
}

static int try_connect(const char *passwd1, const char *passwd2)
{
  MYSQL *mysql= mysql_init(NULL);
  MYSQL *conn;
  FAIL_IF(!mysql, "mysql_init() failed");

  if (plugindir)
    mysql_options(mysql, MYSQL_PLUGIN_DIR, plugindir);

  if (passwd2)
  {
    unsigned int factor= 2;
    mysql_options4(mysql, MYSQL_OPT_USER_PASSWORD, &factor, passwd2);
  }

  conn= mysql_real_connect(mysql, hostname, mfa_user, passwd1,
                           NULL, port, socketname, 0);
  if (!conn)
  {
    diag("connect failed: %s (errno %u)", mysql_error(mysql), mysql_errno(mysql));
    mysql_close(mysql);
    return FAIL;
  }
  mysql_close(mysql);
  return OK;
}

static int test_baseline(MYSQL *conn)
{
  int rc= mysql_query(conn, "SELECT 1");
  FAIL_IF(rc != 0, "SELECT 1 failed on baseline connection");
  mysql_free_result(mysql_store_result(conn));

  if (!check_mfa_support(conn))
    return SKIP;

  return OK;
}

/*
  2-factor MFA: caching_sha2_password + qa_auth_interface.
  CREATE USER syntax differs between MariaDB and MySQL.
*/
static int test_mfa_2factor(MYSQL *conn)
{
  int rc;
  char buf[512];

  if (!check_mfa_support(conn))
    return SKIP;

  if (!ensure_qa_plugin(conn))
    return SKIP;

  drop_users(conn);

  snprintf(buf, sizeof(buf), "CREATE USER '%s' IDENTIFIED BY 'irrelevant'",
           proxy_user);
  rc= mysql_query(conn, buf);
  FAIL_IF(rc != 0, mysql_error(conn));

  if (mariadb_connection(conn))
    snprintf(buf, sizeof(buf),
      "CREATE USER '%s' "
      "IDENTIFIED WITH caching_sha2_password AS PASSWORD('goodpass') "
      "AND qa_auth_interface AS '%s'",
      mfa_user, proxy_user);
  else
    snprintf(buf, sizeof(buf),
      "CREATE USER '%s' "
      "IDENTIFIED WITH caching_sha2_password BY 'goodpass' "
      "AND IDENTIFIED WITH qa_auth_interface AS '%s'",
      mfa_user, proxy_user);

  rc= mysql_query(conn, buf);
  if (rc)
  {
    diag("MFA CREATE USER failed: %s", mysql_error(conn));
    drop_users(conn);
    return SKIP;
  }

  snprintf(buf, sizeof(buf), "GRANT PROXY ON '%s' TO '%s'",
           proxy_user, mfa_user);
  rc= mysql_query(conn, buf);
  FAIL_IF(rc != 0, mysql_error(conn));

  FAIL_IF(try_connect("goodpass", proxy_user) != OK,
          "connect with correct MFA credentials should succeed");

  FAIL_IF(try_connect("bad", proxy_user) == OK,
          "connect with wrong factor-1 password should fail");

  FAIL_IF(try_connect("goodpass", "wrong") == OK,
          "connect with wrong factor-2 secret should fail");

  drop_users(conn);
  mysql_query(conn, "UNINSTALL PLUGIN qa_auth_interface");
  return OK;
}

struct my_tests_st my_tests[] = {
  {"test_baseline",     test_baseline,     TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {"test_mfa_2factor",  test_mfa_2factor,  TEST_CONNECTION_DEFAULT, 0, NULL, NULL},
  {NULL, NULL, 0, 0, NULL, NULL}
};

int main(int argc, char **argv)
{
  if (argc > 1)
    get_options(argc, argv);

  get_envvars();
  run_tests(my_tests);
  return exit_status();
}
