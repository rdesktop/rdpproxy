SOURCES=rdpproxy.c secure.c
LDLIBS=-lcrypto
CFLAGS=-DUSE_X509

all: rdpproxy rsa2der

rdpproxy: $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDLIBS)

rsa2der: rsa2der.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean: 
	rm rdpproxy rsa2der
