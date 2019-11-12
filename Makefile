CC      = gcc
CFLAGS  = -g -O2 -Wall

all: fuse-adfs example

fuse-adfs: fuse-adfs.c
	$(CC) $(CFLAGS) `pkg-config fuse3 --cflags --libs` -o fuse-adfs fuse-adfs.c

example: example.c
	$(CC) $(CFLAGS) `pkg-config fuse3 --cflags --libs` -o example example.c
