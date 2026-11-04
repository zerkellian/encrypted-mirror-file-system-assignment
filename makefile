CC = gcc
CFLAGS = -Wall  `pkg-config fuse3 --cflags`
LIBS = `pkg-config fuse3 --libs`

all: filedir_mirror

filedir_mirror: filedir_mirror_fused.c
	$(CC) $(CFLAGS) -o filedir_mirror filedir_mirror_fused.c $(LIBS) -I.
