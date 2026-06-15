# Cambia questo percorso con la tua installazione di DynamoRIO
DYNAMORIO_HOME ?= /home/frank/Desktop/SS3/DynamoRIO-Linux-11.3.0-1

CC = gcc
CFLAGS = -O2 -Wall
DR_INCLUDES = -I$(DYNAMORIO_HOME)/include -I$(DYNAMORIO_HOME)/ext/include
DR_LIBS = -L$(DYNAMORIO_HOME)/ext/lib64/release/ -ldrmgr -ldrwrap

all: libanti_evasion.so target_app

libanti_evasion.so: anti_evasion.c
	$(CC) $(CFLAGS) -shared -fPIC -DX86_64 -DLINUX $(DR_INCLUDES) anti_evasion.c -o libanti_evasion.so $(DR_LIBS)

target_app: target_app.c
	$(CC) $(CFLAGS) target_app.c -o target_app

clean:
	rm -f libanti_evasion.so target_app
