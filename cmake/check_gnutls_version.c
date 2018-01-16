#include <stdio.h>
#include <gnutls/gnutls.h>

int main()
{
#ifdef GNUTLS_VERSION
  printf("%s", GNUTLS_VERSION);
#endif
  return 0;
}
