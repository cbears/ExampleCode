/* Example OpenSSL code
 * 
 * gcc -g -o example_openssl example_openssl.c -lssl -lcrypto
 *
 * Written by Charles Shiflett
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/ssl.h>
// #include <openssl/store.h>
#include <openssl/engine.h>
#include <openssl/err.h>


#define VRFY(x, a, ...) if (!(x))  {                       \
  char b[1024];                                            \
  int sz;                                                  \
  (void) sz;                                               \
  if (errno) {                                             \
    sz=snprintf(b, 1000, "Err: " a " [%s:%d]: %s\n",       \
      ##__VA_ARGS__, __FILE__, __LINE__, strerror(errno)); \
  } else {                                                 \
    sz=snprintf(b, 1000, "Err " a " [%s:%d]\n",            \
      ##__VA_ARGS__, __FILE__, __LINE__);                  \
  }                                                        \
  write( STDERR_FILENO, b, sz);                            \
  ERR_print_errors_fp(stdout);                             \
  exit(-1);                                                \
}


int connect_socket( char* host, int port ) {
  int fd;
  char port_string[32];

  struct sockaddr_storage sas;
  struct addrinfo *result;
  int res, sz = sizeof(struct sockaddr_in6); 

  snprintf(port_string, 31, "%d", port);

  VRFY( (res=getaddrinfo(host, port_string, NULL, &result)) == 0,
    "Host lookup failed (host='%s',port=%s); %s", host, port_string, gai_strerror(res) );

  memcpy( &sas, result->ai_addr, result->ai_addrlen );
  freeaddrinfo(result);

  fd = socket(sas.ss_family, SOCK_STREAM, 0);

  if ( sas.ss_family == AF_INET )
    sz = sizeof(struct sockaddr_in);

  VRFY( connect(fd, (struct sockaddr *) &sas, sz) == 0, "Error connecting to host" );

  return fd;
}

int main() {

  char host[] = "www.yikes.com";
  int  port = 443;

  SSL_CTX *ctx;
  SSL *ssl;
  int sock = 0;

  ctx = SSL_CTX_new( TLS_client_method() );
  VRFY(ctx, "Creating SSL ctx");

  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

  sock = connect_socket(host, port);

  // User Token
  char pkcs11_id[] = "pkcs11:serial=20f21dac0002800c";
  char PIN[] = "sekret";
  char cert_location[] = "agent.cer"; // ToDo: Use cert on token


  /* Newer systems should use Provider API; 
   *
   * This is not supported, out of the box, on Ubuntu 22.04 so I have not
   * tested anything below, but somthing like this *should* work
   *
   * https://www.saela.eu/openssl/
   *
   * openssl storeutl -engine pkcs11 'pkcs11:'

  { // Do something with PKCS11 using provider API

    OSSL_STORE_CTX *store;
    OSSL_STORE_INFO *info;
    EVP_PKEY *k;

    store = OSSL_STORE_open_ex(pkcs11_id, NULL, "provider=pkcs11", NULL, NULL,
                               NULL, NULL, NULL);

	    
    VRFY( store, "error opening requested PKCS11 store")

    info = OSSL_STORE_load(store);
    VRFY(info, "Got NULL reading OSSL_STORE")
	    
    k = OSSL_STORE_INFO_get1_PKEY(info);


    EVP_PKEY_free(k);
    OSSL_STORE_close(store);

  }
  */

  // Uncomment the following to enable PKCS11 
  /*
  {   
      ENGINE *e; 
      ENGINE_load_builtin_engines();
      e = ENGINE_by_id("pkcs11");
      VRFY( e, "Error loading pkcs11 engine" );

      ENGINE_ctrl_cmd_string(e, "PIN", PIN, 0);

      VRFY( ENGINE_init(e) != 0, "Error initializing engine");

      EVP_PKEY* priv_key = ENGINE_load_private_key(e, pkcs11_id, NULL, NULL);
      VRFY( priv_key, "Error loading private key");

      SSL_CTX_use_PrivateKey( ctx, priv_key );
      SSL_CTX_use_certificate_file( ctx, cert_location, SSL_FILETYPE_PEM );

  }
  */

  // Enable host name verification
  SSL_CTX_set_default_verify_paths(ctx);
  X509_VERIFY_PARAM_set1_host(SSL_CTX_get0_param(ctx), host, strlen(host));
  SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER, NULL );


  ssl = SSL_new(ctx);

  // Comment to disable SNI. SNI sends host in clear text to server.
  // Ideally if you need SNI, you should be using ECH, but ECH support
  // is not present in most builds of OpenSSL. Phrased another way, you
  // really should disable SNI unless you need it.

  SSL_set_tlsext_host_name(ssl, host);

  /* // If OpenSSL is compiled with SSL_trace, you can enable debugging:
  SSL_set_msg_callback(ssl, SSL_trace);
  SSL_set_msg_callback_arg(ssl, BIO_new_fp(stderr, 0));
  */

  SSL_set_fd(ssl, sock);

  VRFY ( SSL_connect(ssl) == 1, "Layering SSL on top of socket" );

  {  // Example request
    char GET_HTTP[256];
    int sz;
    char buf[512];

    snprintf(GET_HTTP, 255,  "GET / HTTP/1.1\nHost: %s\nConnection: close\n\n", host );
    SSL_write(ssl, GET_HTTP, sizeof(GET_HTTP)-1);
    sz=SSL_read(ssl, buf, 512);
    printf("Output:\n%.*s\n", sz, buf );
  }

  SSL_free(ssl);
  close(sock);
  SSL_CTX_free(ctx);
  printf("Exiting successfully...\n");
  return(0);
}
