# Makefile for Server Program

# 編譯器
CXX = g++

# 編譯選項
CXXFLAGS = -Wall -Wextra -std=c++11 -g

# 需要鏈接的庫
LIBS = -lssl -lcrypto -lpthread

# 目標檔案名稱
TARGET = server

# 來源檔案
SRC = server.cpp

# 建立目標
all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# 清理編譯產物
clean:
	rm -f $(TARGET)

# 聲明偽目標
.PHONY: all clean
