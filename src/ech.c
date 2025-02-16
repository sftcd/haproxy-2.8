/*
 * ECH utility functions
 *
 * Copyright 2023 Stephen Farrell <stephen.farrell@cs.tcd.ie>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#ifdef USE_ECH

# include <haproxy/buf-t.h>
# include <haproxy/ech.h>
# include <openssl/err.h>
# include <dirent.h>
# include <sys/stat.h>

static int innerouter_cmp(ech_state_t *ech_state, char *io, int isinner)
{
    char *svar = NULL;

    if (isinner == 1 && ech_state->calls == 0) {
        ech_state->inner_sni = io;
        return 1;
    }
    if (isinner == 0 && ech_state->calls == 0) {
        ech_state->outer_sni = io;
        return 1;
    }

    if (isinner) 
        svar = ech_state->inner_sni;
    else
        svar = ech_state->outer_sni;
    /* check/copy new inner */
    if (svar != NULL) {
        if (io == NULL) {
            return 0;
        } else {
            size_t iolen = strlen(io);
            size_t slen = strlen(svar);
            if (iolen != slen) {
                return 0;
            } 
            if (strncmp(io, svar, slen)) {
                return 0;
            }
            OPENSSL_free(io);
        }
    } else {
        if (io != NULL) {
            OPENSSL_free(io);
            return 0;
        }
    }
    return 1;
}

int attempt_split_ech(ech_state_t *ech_state,
                      unsigned char *data, size_t bleft,
                      int *dec_ok,
                      unsigned char **newdata, size_t *newlen)
{
    size_t chlen = 0, hs_len = 0, extra_data = 0;
    unsigned char *ch = data, *orig = data;
    int srv = 0, isccs = 0;
    char *newinner = NULL, *newouter = NULL;

	/* Check for SSL/TLS Handshake */
	if (!bleft)
		goto err;

	if (*data != 0x16 && *data != 0x14)
		goto err;
    if (*data == 0x14) {
        isccs = 1; /* we have a fakey change cipher suite */
        data += 6;
        ch = data;
        bleft -= 6;
    }
	/* Check for SSLv3 or later (SSL version >= 3.0) in the record layer*/
	if (bleft < 3)
		goto err;
	if (data[1] < 0x03)
		goto err;
	if (bleft < 5)
		goto err;
	hs_len = (data[3] << 8) + data[4];
    chlen=hs_len+5;
	if (hs_len < 1 + 3 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 2)
		goto err;
	data += 5; /* enter TLS handshake */
	bleft -= 5;
	/* Check for a complete client hello starting at <data> */
	if (bleft < 1)
		goto err;
	if (data[0] != 0x01) /* msg_type = Client Hello */
		goto err;
	/* Check the Hello's length */
	if (bleft < 4)
		goto err;
	hs_len = (data[1] << 16) + (data[2] << 8) + data[3];
	if (hs_len < 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 2)
		goto err;
	/* We want the full handshake here */
	if (bleft < hs_len)
		goto err;
    /* handle early data */
    if (bleft > chlen)
        extra_data = bleft + 5 - chlen;
    *newlen = chlen + (isccs ? 6 : 0) + extra_data;
    *newdata = OPENSSL_malloc(*newlen);
    if (*newdata == NULL)
		goto err;
    if (isccs) {
        memcpy(*newdata, orig, 6);
    }
    /*
     * We'll clear OpenSSL errors here (for now).
     * TODO: check if this is ok, it seems wrong;-(
     */
    ERR_clear_error();
    /* Attempt to decrypt and retrieve inner/outer SNI values */
    srv = SSL_CTX_ech_raw_decrypt(ech_state->ctx, dec_ok,
                                  &newinner, &newouter,
                                  ch, chlen,
                                  (*newdata + (isccs ? 6 : 0)), newlen,
                                  &ech_state->hrrtok, &ech_state->toklen);
    if (srv != 1) {
        OPENSSL_free(*newdata);
        return srv;
    }
    if (srv == 1 && isccs)
        *newlen += 6;
    /* add back early data if it was there */
    if (extra_data > 0) {
        memcpy(*newdata + (isccs ? 6 : 0) + *newlen,
               orig + (isccs ? 6: 0) + chlen, extra_data);
        *newlen += extra_data;
    }

    srv = innerouter_cmp(ech_state, newinner, 1);
    if (srv != 1)
        return srv;
    srv = innerouter_cmp(ech_state, newouter, 0);
    if (srv != 1)
        return srv;
    return 1;
err:
    return 0;
}

void ech_state_free(ech_state_t *st)
{
    if (st == NULL)
        return;
    /* st->ctx is a shallow copy, so doesn't need freeing */
    OPENSSL_free(st->hrrtok);
    OPENSSL_free(st->inner_sni);
    OPENSSL_free(st->outer_sni);
    return;
}

/* 
 * load any key files called <name>.ech we find in the named
 * directory 
 */
int load_echkeys(SSL_CTX *ctx, char *dirname, int *loaded)
{
    struct dirent **de_list = NULL;
    struct stat thestat;
    /*
     * I really can't see a reason to want >1024 private key files
     * to have to be checked in a directory, but if there were a
     * reason then you could change this I guess or make it a 
     * config setting.
     */
    int rv = 0, i, nrv, somekeyworked = 0, maxkeyfiles=1024;
    char *den = NULL, *last4 = NULL, privname[PATH_MAX];
    size_t elen = 0, nlen = 0;
    OSSL_ECHSTORE * const es = OSSL_ECHSTORE_new(NULL, NULL);

    if (es == NULL)
        goto end;
    nrv = scandir(dirname, &de_list, 0, alphasort);
    if (nrv < 0)
        goto end;
    for (i = 0; i != nrv; i++) {
        struct dirent *de = de_list[i];

        den = de->d_name;
        nlen = strlen(den);
        if (nlen > 4) {
            last4 = den + nlen - 4;
            if (strncmp(last4, ".ech", 4))
                goto ignore_entry;
            if ((elen + 1 + nlen + 1) >= PATH_MAX)
                goto ignore_entry;
            snprintf(privname, PATH_MAX,"%s/%s", dirname, den);
            if (!--maxkeyfiles) /* just so we don't loop forever, ever */
                return 0;
            if (stat(privname, &thestat) == 0) {
                BIO *in = BIO_new_file(privname, "r");
                const int is_retry_config = OSSL_ECH_FOR_RETRY;

                if (in != NULL
                    && 1 == OSSL_ECHSTORE_read_pem(es, in, is_retry_config))
                    somekeyworked = 1;
                BIO_free_all(in);
            }
        }
ignore_entry:
        free(de);
    }

    if (somekeyworked == 0)
        goto end;
    if (OSSL_ECHSTORE_num_keys(es, loaded) != 1)
        goto end;
    if (1 != SSL_CTX_set1_echstore(ctx, es))
        goto end;
    rv = 1;
end:
    free(de_list);
    OSSL_ECHSTORE_free(es);
    return rv;
}
#endif /* USE_ECH */
