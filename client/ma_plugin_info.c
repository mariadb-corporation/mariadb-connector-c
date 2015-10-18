
#include <my_global.h>
#include <my_sys.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <getopt.h>
#include <stdio.h>
#include <my_dir.h>
#include <string.h>

static struct option long_options[]=
{
  {"builtin", no_argument, 0, 'b'},
  {"dynamic", no_argument, 0, 'd'},
  {"all", no_argument, 0, 'a'},
  {"plugin", 1, 0, 'p'},
  {NULL, 0, 0, 0}
};

struct st_plugin_type
{
  int type;
  char *typename;
};

static struct st_plugin_type plugin_types[]=
{
  {MYSQL_CLIENT_AUTHENTICATION_PLUGIN, "authentication"},
  {MARIADB_CLIENT_CIO_PLUGIN, "client/server protocol"},
  {MARIADB_CLIENT_TRACE_PLUGIN, "trace"},
  {MARIADB_CLIENT_REMOTEIO_PLUGIN, "remote file access"},
  {MARIADB_CLIENT_CONNECTION_PLUGIN, "connection handler"},
  {0, "unknown"}
};

static void usage(void)
{
  int i=0;
  puts("Copyright 2015 MariaDB Corporation AB");
  puts("Show client plugin information for MariaDB Connector/C.");
  printf("Usage: %s [OPTIONS] [plugin_name]\n", my_progname);
  while (long_options[i].name)
  {
    printf("  --%-12s -%c\n", long_options[i].name, long_options[i].val);
    i++;
  }
}

static char *get_type_name(int type)
{
  int i=0;
  while (plugin_types[i].type)
  {
    if (type== plugin_types[i].type)
      return plugin_types[i].typename;
    i++;
  }
  return plugin_types[i].typename;
}

static void show_plugin_info(struct st_mysql_client_plugin *plugin, my_bool builtin)
{
  printf("Type: %s\n", get_type_name(plugin->type));
  printf("Name: %s\n", plugin->name);
  printf("Desc: %s\n", plugin->desc);
  printf("Author: %s\n", plugin->author);
  printf("License: %s\n", plugin->license);
  printf("Version: %d.%d.%d\n", plugin->version[0], plugin->version[1], plugin->version[2]);
  printf("API Version: 0x%04X\n", plugin->interface_version);
  printf("Build type: %s\n", builtin ? "builtin" : "dynamic");
  printf("\n");
}

static void show_builtin()
{
  struct st_mysql_client_plugin **builtin;

  for (builtin= mysql_client_builtins; *builtin; builtin++)
    show_plugin_info(*builtin, TRUE);
}

static void show_file(char *filename)
{
  char dlpath[FN_REFLEN+1];
  void *sym, *dlhandle;
  struct st_mysql_client_plugin *plugin;
  char *env_plugin_dir= getenv("MARIADB_PLUGIN_DIR");
  char *has_so_ext= strstr(filename, SO_EXT);

  if (!strchr(filename, FN_LIBCHAR))
    strxnmov(dlpath, sizeof(dlpath) - 1,
             (env_plugin_dir) ? env_plugin_dir : PLUGINDIR, "/", filename, has_so_ext ? "" : SO_EXT, NullS);
  else
    strcpy(dlpath, filename);
  if ((dlhandle= dlopen((const char *)dlpath, RTLD_NOW)))
  {
    if (sym= dlsym(dlhandle, plugin_declarations_sym))
    {
      plugin= (struct st_mysql_client_plugin *)sym;
      show_plugin_info(plugin, 0);
    }
    dlclose(dlhandle);
  }
}

static void show_dynamic()
{
  MY_DIR *dir= NULL;
  int i;
  char *env_plugin_dir= getenv("MARIADB_PLUGIN_DIR");

  dir= my_dir(env_plugin_dir ? env_plugin_dir : PLUGINDIR, 0);

  if (!dir->number_off_files)
  {
    printf("No plugins found in %s\n", env_plugin_dir ? env_plugin_dir : PLUGINDIR);
    return;
  }

  for (i=0; i < dir->number_off_files; i++)
  {
    char *p= strstr(dir->dir_entry[i].name, SO_EXT);
    if (p)
      show_file(dir->dir_entry[i].name);
  }
  if (dir)
    my_dirend(dir);
}

int main(int argc, char *argv[])
{
  int option_index= 0;
  int c;
  my_progname= argv[0];

  if (argc <= 1)
  {
    usage();
    exit(1);
  }

  c= getopt_long(argc, argv, "bdap", long_options, &option_index);

  switch(c) {
  case 'a': /* all */
    show_builtin();
    show_dynamic();
    break;
  case 'b': /* builtin */
    show_builtin();
    break;
  case 'd': /* dynamic */
    show_dynamic();
    break;
  case 'p':
    if (argc > 2)
    {
      show_file(argv[2]);
      break;
    }
  default:
    usage();
    exit(1);
  }

}
