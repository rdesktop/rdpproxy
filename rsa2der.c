#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/rsa.h>

/* reverse an array in situ */
void
reverse(unsigned char *p, unsigned int len)
{
	char temp;
	int i, j;

	for (i = 0, j = len - 1; i < j; i++, j--)
	{
		temp = p[i];
		p[i] = p[j];
		p[j] = temp;
	}
}

int
read_file(char *filename, unsigned char *buffer, unsigned int maxlen)
{
	int fd, len;

	fd = open(filename, O_RDONLY);
	if (fd == -1)
	{
		perror(filename);
		return -1;
	}

	len = read(fd, buffer, maxlen);
	close(fd);
	return len;
}

int
write_file(char *filename, unsigned char *buffer, unsigned int len)
{
	int fd;

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
	{
		perror(filename);
		return -1;
	}

	len = write(fd, buffer, len);
	close(fd);
	return len;
}

BIGNUM *
parse_bignum(unsigned char **buf, unsigned int len)
{
	BIGNUM *bn;

	reverse(*buf, len);
	bn = BN_bin2bn(*buf, len, NULL);
	*buf += len;

	return bn;
}

RSA *
parse_rsa2(unsigned char *buf, unsigned int len)
{
	RSA *rsa;
	unsigned int modlen;

	if (strncmp(buf, "RSA2", 4) != 0)
	{
		fprintf(stderr, "Not an RSA2 private key\n");
		return NULL;
	}

	/* FIXME: should be a DWORD */
	modlen = *(buf + 4);
	if (len < (20 + (9 * modlen / 2)))
	{
		fprintf(stderr, "Input file truncated?\n");
		return NULL;
	}

	buf += 16;

	rsa = RSA_new();
	if (rsa == NULL)
		return NULL;

	rsa->e = parse_bignum(&buf, 4);
	rsa->n = parse_bignum(&buf, modlen);
	rsa->p = parse_bignum(&buf, modlen / 2);
	rsa->q = parse_bignum(&buf, modlen / 2);
	rsa->dmp1 = parse_bignum(&buf, modlen / 2);
	rsa->dmq1 = parse_bignum(&buf, modlen / 2);
	rsa->iqmp = parse_bignum(&buf, modlen / 2);
	rsa->d = parse_bignum(&buf, modlen);

	return rsa;
}

int
main(int argc, char *argv[])
{
	unsigned char buffer[1024];
	unsigned char *p = buffer;
	unsigned int len;
	RSA *rsa;

	if (argc < 3)
	{
		fprintf(stderr, "Usage: %s <infile> <outfile>\n", argv[0]);
		return 0;
	}

	if ((len = read_file(argv[1], buffer, sizeof(buffer))) == -1)
	{
		fprintf(stderr, "Failed to read file\n");
		return 1;
	}

	if ((rsa = parse_rsa2(buffer, len)) == NULL)
	{
		fprintf(stderr, "Failed to parse RSA key\n");
		return 1;
	}

	len = i2d_RSAPrivateKey(rsa, &p);
	if (write_file(argv[2], buffer, len) == -1)
	{
		fprintf(stderr, "Failed to write file\n");
		return 1;
	}

	return 0;
}
