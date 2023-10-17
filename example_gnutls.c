/*  Code showing how to use GnuTLS library. Specific examples given include:
 *  how to enabling logging, using PKCS11 tokens, verifying server certificate,
 *  making a HTTP GET request, and adding CA from file.  Compile with:
 * 
 *    gcc -o example_gnutls -g example_gnutls.c -lgnutls
 *
 *  Written by Charles Shiflett.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/pkcs11.h>

char sekret_pin[] = "SEKRET PIN"; // For PKCS11 token (if enabled)
char host[] = "www.yikes.com";

/* If using this with a PKCS11 token; the KEY_URL and CERT_URL are PKCS11
 * IDs defined in RFC 7512. You can alternatively specify as a file or URL.
 * 
 * To get the PKCS11 ID of your token, one approach is to use
 * 
 *   $ p11tool --list-tokens
 *   ... Displays tokens in system
 *   $ p11tool --login --list-all "pkcs11:serial=20f2171d8002800d"
 *   ... PKCS11 URL for certificates
 * 
 * Where pkcs11:serial is derived from the output of p11tool --list-tokens.
 * Note the quotations, which are typically needed.
 */

char KEY_URL[] = "pkcs11:serial=20f2174b8002800f;type=private";
char CERT_URL[] =  "pkcs11:serial=20f2174b8002800f;type=cert";

int  port = 443;
 
#define VRFY(x, a, ...) if (!(x))  {                       \
  if (errno) {                                             \
    fprintf(stderr, "Err: " a " [%s:%d]: %s\n",            \
      ##__VA_ARGS__, __FILE__, __LINE__, strerror(errno)); \
  } else {                                                 \
    fprintf(stderr, "Err " a " [%s:%d]\n",                 \
      ##__VA_ARGS__, __FILE__, __LINE__);                  \
  }                                                        \
  exit(-1);                                                \
}

#define G_VRFY(x, a, ...) if (x!=GNUTLS_E_SUCCESS)  {      \
  fprintf(stderr, "Err: " a " [%s:%d]: %s (%s)\n",         \
   ##__VA_ARGS__, __FILE__, __LINE__, gnutls_strerror(x),  \
   gnutls_strerror_name(x));                               \
  exit(-1);                                                \
}

int connect_socket( char* host, int port ) {
  int fd;
  char port_string[32];

  struct sockaddr_storage sas;
  struct addrinfo *result;
  int res, sz = sizeof(struct sockaddr_in6); 

  snprintf(port_string, 31, "%d", port);

  res = getaddrinfo(host, port_string, NULL, &result);
  VRFY( res == 0, "Host lookup failed (host='%s',port=%s); %s",
        host, port_string, gai_strerror(res) );

  memcpy( &sas, result->ai_addr, result->ai_addrlen );
  freeaddrinfo(result);

  fd = socket(sas.ss_family, SOCK_STREAM, 0);

  if ( sas.ss_family == AF_INET )
    sz = sizeof(struct sockaddr_in);

  res = connect(fd, (struct sockaddr *) &sas, sz); 
  VRFY( res == 0, "Error connecting to host" );

  return fd;
}

// pin_callback for PKCS11 token (if enabled)
static int pin_callback(void *user, int attempt, const char *token_url,
			const char *token_label, unsigned int flags, char *pin,
			size_t pin_max)
{
	static int pin_count=0;

  VRFY( pin_count++==0, "Incorrect PIN");
	printf("In pin_callback. \n");
  
  // Typically you would read password using getpass() or similar
  strncpy( pin, sekret_pin, pin_max );
	return 0;
}

void log_func (int level, const char *str) {
  fprintf (stderr, "[%d] %s", level, str);
}

int main() {

  gnutls_session_t ctx;
  int sock = 0;

  gnutls_pkcs11_set_pin_function( pin_callback, NULL );

  // Uncomment to enable logging; 
  /*
  gnutls_global_set_log_level (10);
  gnutls_global_set_log_function (log_func);
  */

  G_VRFY(gnutls_init(&ctx, GNUTLS_CLIENT), "Creating SSL ctx");
  G_VRFY(gnutls_set_default_priority(ctx), "Set default priority");

  gnutls_certificate_credentials_t xcred;
  gnutls_certificate_allocate_credentials(&xcred);
  gnutls_certificate_set_x509_system_trust(xcred); // Load system CA's

  // Uncomment out the following line to enable PKCS11
  // SSL Client Certificate Authentication using token

  /*
  G_VRFY(gnutls_certificate_set_x509_key_file(xcred, CERT_URL, KEY_URL,
						   GNUTLS_X509_FMT_DER),
         "setting PKCS11 key file/cert");
  */

  //  Uncomment the following line to add CA(s) from file "keystore.pem"

  /*
  gnutls_certificate_set_x509_trust_file(xcred, "keystore.pem", GNUTLS_X509_FMT_PEM);
  */

  gnutls_credentials_set(ctx, GNUTLS_CRD_CERTIFICATE, xcred);
  gnutls_server_name_set(ctx, GNUTLS_NAME_DNS, host, strlen(host)); // For SNI

  // NOTE: Unless needed, you shouldn't use SNI as it exposes the server name in
  // plain text. As of 2023-10-01; ECH is not supported in released versions of
  // GnuTLS

  // Comment out this line to disable host verification
  gnutls_session_set_verify_cert(ctx, host, 0);

  // We setup our socket only after we have finished with token initialization.
  // Otherwise we hit a condition where our TLS session times out before token
  // can be initialized.
  sock = connect_socket(host, port);

  gnutls_transport_set_int(ctx, sock);
  gnutls_handshake_set_timeout(ctx, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

  G_VRFY(gnutls_handshake(ctx), "Initializing TLS session");

  printf("Session: %s\n", gnutls_session_get_desc(ctx));

  {  // Example HTTP request
    char GET_HTTP[256];
    int sz;
    char buf[512];

    snprintf(GET_HTTP, 255,  "GET / HTTP/1.1\nHost: %s\nConnection: close\n\n", host );
    sz=gnutls_record_send(ctx, GET_HTTP, sizeof(GET_HTTP)-1);
    VRFY(sz == (sizeof(GET_HTTP)-1), "Sending data");
    sz=gnutls_record_recv(ctx, buf, 512);
    while (sz == GNUTLS_E_AGAIN) {
      sz=gnutls_record_recv(ctx, buf, 512);
    }

    if (sz<0) {
      G_VRFY(sz, "Receving data");
    }

    printf("Output:\n%.*s\n", sz, buf );
  }

  return(0);
}

