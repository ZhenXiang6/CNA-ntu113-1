# Makefile for Client Program

# 變數定義
CC = gcc
CFLAGS = -Wall -g
TARGET = client
SRC = client.c

# 預設目標
all: $(TARGET)

# 編譯目標
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# 清除編譯產生的檔案
clean:
	rm -f $(TARGET) *.o

# 重新編譯
rebuild: clean all

# .PHONY 標記非檔案目標
.PHONY: all clean rebuild
