#include <stdexcept>

#include <openssl/ec.h>
#include <openssl/evp.h>

unsigned char *ecdh(size_t *secret_len) {
  EVP_PKEY_CTX *pctx, *kctx;
  EVP_PKEY_CTX *ctx;
  unsigned char *secret;
  EVP_PKEY *pkey = NULL, *peerkey, *params = NULL;
  /* NB: assumes pkey, peerkey have been already set up */

  /* Create the context for parameter generation */
  if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
    throw std::runtime_error("ecdh failed.");
  }

  /* Initialise the parameter generation */
  if (1 != EVP_PKEY_paramgen_init(pctx)) {
    throw std::runtime_error("ecdh failed.");
  }

  /* We're going to use the ANSI X9.62 Prime 256v1 curve */
  if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) {
    throw std::runtime_error("ecdh failed.");
  }

  /* Create the parameter object params */
  if (!EVP_PKEY_paramgen(pctx, &params)) {
    throw std::runtime_error("ecdh failed.");
  }

  /* Create the context for the key generation */
  if (NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) {
    throw std::runtime_error("ecdh failed.");
  }

  /* Generate the key */
  if (1 != EVP_PKEY_keygen_init(kctx)) {
    throw std::runtime_error("ecdh failed.");
  }
  if (1 != EVP_PKEY_keygen(kctx, &pkey)) {
    throw std::runtime_error("ecdh failed.");
  }

  /* Get the peer's public key, and provide the peer with our public key -
   * how this is done will be specific to your circumstances */
  peerkey = get_peerkey(pkey);

  /* Create the context for the shared secret derivation */
  if (NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) {
    throw std::runtime_error("ecdh failed.");
  }

  /* Initialise */
  if (1 != EVP_PKEY_derive_init(ctx)) {
    throw std::runtime_error("ecdh failed.");
  }

  /* Provide the peer public key */
  if (1 != EVP_PKEY_derive_set_peer(ctx, peerkey)) {
    throw std::runtime_error("ecdh failed.");
  }

  /* Determine buffer length for shared secret */
  if (1 != EVP_PKEY_derive(ctx, NULL, secret_len)) {
    throw std::runtime_error("ecdh failed.");
  }

  /* Create the buffer */
  if (NULL == (secret = (unsigned char *)OPENSSL_malloc(*secret_len))) {
    throw std::runtime_error("ecdh failed.");
  }

  /* Derive the shared secret */
  if (1 != (EVP_PKEY_derive(ctx, secret, secret_len))) {
    throw std::runtime_error("ecdh failed.");
  }

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(peerkey);
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(kctx);
  EVP_PKEY_free(params);
  EVP_PKEY_CTX_free(pctx);

  /* Never use a derived secret directly. Typically it is passed
   * through some hash function to produce a key */
  return secret;
}