prefix=/home/azhen/EECS588/libsodium-bin
libdir=$(prefix)/lib
includedir=$(prefix)/include

LIBS=-L$(libdir) -Wl,-rpath=$(libdir) -lsodium 
#LIBS=-static -L. libsodium.a
CFLAGS=-I$(includedir) -std=c99

all: test4

test2: test2.o debug_io.o
	$(CC) -pthread $^ -o $@

test3: test3.o 
	$(CC) $(LIBS) $^ -o $@

test4: test4.o 
	$(CC) $(LIBS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
