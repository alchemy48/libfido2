/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/ec.h>
#include <openssl/pem.h>

#include <fcntl.h>
#include <hidapi.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fido.h"
#include "compat.h"
#include "extern.h"

static const unsigned char cdh[32] = {
	0xf9, 0x64, 0x57, 0xe7, 0x2d, 0x97, 0xf6, 0xbb,
	0xdd, 0xd7, 0xfb, 0x06, 0x37, 0x62, 0xea, 0x26,
	0x20, 0x44, 0x8e, 0x69, 0x7c, 0x03, 0xf2, 0x31,
	0x2f, 0x99, 0xdc, 0xaf, 0x3e, 0x8a, 0x91, 0x6b,
};

static const unsigned char user_id[32] = {
	0x78, 0x1c, 0x78, 0x60, 0xad, 0x88, 0xd2, 0x63,
	0x32, 0x62, 0x2a, 0xf1, 0x74, 0x5d, 0xed, 0xb2,
	0xe7, 0xa4, 0x2b, 0x44, 0x89, 0x29, 0x39, 0xc5,
	0x56, 0x64, 0x01, 0x27, 0x0d, 0xbb, 0xc4, 0x49,
};

static void
usage(void)
{
	fprintf(stderr, "usage: cred [-ruv] [-P pin] [-k pubkey] [-ei cred_id] "
	    "<device>\n");
	exit(EXIT_FAILURE);
}

static void
verify_cred(const char *fmt, const unsigned char *authdata_ptr,
    size_t authdata_len, const unsigned char *x509_ptr, size_t x509_len,
    const unsigned char *sig_ptr, size_t sig_len, bool rk, bool uv,
    const char *key_out, const char *id_out)
{
	fido_cred_t	*cred;
	int		 r;

	if ((cred = fido_cred_new()) == NULL)
		errx(1, "fido_cred_new");

	/* client data hash */
	r = fido_cred_set_clientdata_hash(cred, cdh, sizeof(cdh));
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_clientdata_hash: %s (0x%x)",
		    fido_strerr(r), r);

	/* authdata */
	r = fido_cred_set_authdata(cred, authdata_ptr, authdata_len);
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_authdata: %s (0x%x)", fido_strerr(r), r);

	/* options */
	r = fido_cred_set_options(cred, rk, uv);
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_options: %s (0x%x)", fido_strerr(r), r);

	/* x509 */
	r = fido_cred_set_x509(cred, x509_ptr, x509_len);
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_x509: %s (0x%x)", fido_strerr(r), r);

	/* sig */
	r = fido_cred_set_sig(cred, sig_ptr, sig_len);
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_sig: %s (0x%x)", fido_strerr(r), r);

	/* fmt */
	r = fido_cred_set_fmt(cred, fmt);
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_fmt: %s (0x%x)", fido_strerr(r), r);

	r = fido_cred_verify(cred);
	if (r != FIDO_OK)
		errx(1, "fido_cred_verify: %s (0x%x)", fido_strerr(r), r);

	if (key_out != NULL) {
		/* extract the credential pubkey */
		if (write_ec_pubkey(key_out, fido_cred_pubkey(cred)) < 0)
			errx(1, "write_pubkey");
	}

	if (id_out != NULL) {
		/* extract the credential id */
		if (write_blob(id_out, fido_cred_id_ptr(cred),
		    fido_cred_id_len(cred)) < 0)
			errx(1, "write_blob");
	}

	fido_cred_free(&cred);
}

static int snoop_fd_r;

static void *
hid_open_wrapper(const char *path)
{
#if 0
	if ((snoop_fd_r = open("/tmp/snoop_r", O_WRONLY | O_CREAT, 0644)) < 0)
		return (NULL);
#endif
	if ((snoop_fd_r = dup(fileno(stdin))) < 0)
		return (NULL);

	(void)path;

	return ((void *)-1);
#if 0
	return ((void *)hid_open_path(path));
#endif
}

static void
hid_close_wrapper(void *handle)
{
	close(snoop_fd_r);

	(void)handle;

#if 0
	hid_close(handle);
#endif
}

static int
hid_read_wrapper(void *handle, unsigned char *buf, size_t len, int ms)
{
	int r;

	(void)handle;
	(void)ms;

	r = (int)read(snoop_fd_r, buf, len);
#if 0
	r = hid_read_timeout(handle, buf, len, ms);

	if (r > 0)
		(void)write(snoop_fd_r, buf, r);
#endif

	return (r);
}

static int
hid_write_wrapper(void *handle, const unsigned char *buf, size_t len)
{
	(void)handle;
	(void)buf;

	return ((int)len);
#if 0
	return (hid_write(handle, buf, len));
#endif
}

int
main(int argc, char **argv)
{
	bool		 rk = false;
	bool		 uv = false;
	bool		 u2f = false;
	fido_dev_t	*dev;
	fido_cred_t	*cred = NULL;
	const char	*pin = NULL;
	const char	*key_out = NULL;
	const char	*id_out = NULL;
	unsigned char	*body = NULL;
	size_t		 len;
	int		 ch;
	int		 r;

	if ((cred = fido_cred_new()) == NULL)
		errx(1, "fido_cred_new");

	while ((ch = getopt(argc, argv, "P:e:i:k:ruv")) != -1) {
		switch (ch) {
		case 'P':
			pin = optarg;
			break;
		case 'e':
			if (read_blob(optarg, &body, &len) < 0)
				errx(1, "read_blob: %s", optarg);
			r = fido_cred_exclude(cred, body, len);
			if (r != FIDO_OK)
				errx(1, "fido_cred_exclude: %s (0x%x)",
				    fido_strerr(r), r);
			free(body);
			body = NULL;
			break;
		case 'i':
			id_out = optarg;
			break;
		case 'k':
			key_out = optarg;
			break;
		case 'r':
			rk = true;
			break;
		case 'u':
			u2f = true;
			break;
		case 'v':
			uv = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	fido_init();

	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");

	fido_dev_io_t io;

	io.open = hid_open_wrapper;
	io.close = hid_close_wrapper;
	io.read = hid_read_wrapper;
	io.write = hid_write_wrapper;

	/* XXX temp */
	fido_dev_set_io_functions(dev, &io);

	if ((r = fido_dev_open(dev, argv[0])) != FIDO_OK)
		errx(1, "fido_dev_open: %s (0x%x)", fido_strerr(r), r);
	if (u2f)
		fido_dev_force_u2f(dev);

	/* client data hash */
	r = fido_cred_set_clientdata_hash(cred, cdh, sizeof(cdh));
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_clientdata_hash: %s (0x%x)",
		    fido_strerr(r), r);

	/* relying party */
	r = fido_cred_set_rp(cred, "localhost", "sweet home localhost");
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_rp: %s (0x%x)", fido_strerr(r), r);

	/* user */
	r = fido_cred_set_user(cred, user_id, sizeof(user_id), "john smith",
	    "jsmith", NULL);
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_user: %s (0x%x)", fido_strerr(r), r);

	/* options */
	r = fido_cred_set_options(cred, rk, uv);
	if (r != FIDO_OK)
		errx(1, "fido_cred_set_options: %s (0x%x)", fido_strerr(r), r);

	r = fido_dev_make_cred(dev, cred, pin);
	if (r != FIDO_OK)
		errx(1, "fido_makecred: %s (0x%x)", fido_strerr(r), r);
	r = fido_dev_close(dev);
	if (r != FIDO_OK)
		errx(1, "fido_dev_close: %s (0x%x)", fido_strerr(r), r);

	fido_dev_free(&dev);

	verify_cred(fido_cred_fmt(cred), fido_cred_authdata_ptr(cred),
	    fido_cred_authdata_len(cred), fido_cred_x5c_ptr(cred),
	    fido_cred_x5c_len(cred), fido_cred_sig_ptr(cred),
	    fido_cred_sig_len(cred), rk, uv, key_out, id_out);

	fido_cred_free(&cred);

	exit(0);
}
