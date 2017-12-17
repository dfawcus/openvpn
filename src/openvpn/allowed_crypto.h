/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2010-2016 Fox Crypto B.V. <openvpn@fox-it.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/**
 * @file Restricted ciphers and digests code file.
 */

#ifndef _FOXIT_ALLOWED_CRYPTO_H_
#define _FOXIT_ALLOWED_CRYPTO_H_

#ifdef ENABLE_CRYPTO

#ifdef ENABLE_CRYPTO_MBEDTLS
#include <mbedtls/ssl.h>

/**
 * List of allowed TLS ciphers.
 *
 * Lists the TLS cipher suites which can be used by the mbed TLS
 * implementation. The are restricted by setting the allowed_ciphers
 * in tls_root_ctx.
 */
static const int allowed_tls_cipher_suites[] = {
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    0
};
static const size_t num_allowed_tls_cipher_suites =
    sizeof(allowed_tls_cipher_suites)/sizeof(*allowed_tls_cipher_suites) - 1;

#else
/**
 * List of allowed TLS ciphers.
 *
 * This string lists the ciphers which can be used by the OpenSSL
 * TLS implementation.  The ciphers that OpenSSL will use are
 * restricted by passing this string to the
 * \c SSL_CTX_set_cipher_list() function.
 */
static const char *allowed_tls_ciphers =
    "SSL-EDH-RSA-AES-256-SHA";
#endif


/**
 * Check whether a given cipher name is allowed.
 *
 * @param name - the cipher name to check.
 * @return 1 if the cipher is acceptable, otherwise return 0.
 */
int is_allowed_data_channel_cipher(const char *name);


/**
 * Check whether a given digest name is allowed.
 *
 * @param name - the digest name to check.
 * @return 1 if the digest is acceptable, otherwise return 0.
 */
int is_allowed_data_channel_digest(const char *name);

/**
 * Check whether a given digest name is allowed.
 *
 * @param name - the digest name to check.
 * @return 1 if the digest is acceptable, otherwise return 0.
 */
int is_allowed_prng_digest(const char *name);

#ifdef ENABLE_CRYPTO_MBEDTLS
/*
 * Check whether a given TLS cipher name is listed as allowed.
 * Return 1 if the digest is allowed, otherwise return 0
 */
int is_allowed_tls_cipher(const char *name);
#endif

#endif /* ENABLE_CRYPTO */
#endif /* _FOXIT_ALLOWED_CRYPTO_H_ */
