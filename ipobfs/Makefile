CC ?= gcc
CFLAGS ?= -s -O3
LIBS = -lnetfilter_queue -lnfnetlink -lcap
SRC_FILES = *.c

all: ipobfs

ipobfs: $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f ipobfs *.o
