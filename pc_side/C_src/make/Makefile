CC=gcc
CFLAGS=-Wall -O2
LDFLAGS=-lws2_32
SRC=../pc_server.c
OUT=pc_server.exe

all: $(OUT)

$(OUT): $(SRC)
    $(CC) $(CFLAGS) -o $(OUT) $(SRC) $(LDFLAGS)

clean:
    if exist $(OUT) del $(OUT)
