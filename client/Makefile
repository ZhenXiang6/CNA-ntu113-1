# Makefile for Client Program

# 編譯器
CXX = g++

# 編譯選項
CXXFLAGS = -Wall -g -std=c++11

# 需要鏈接的庫
LIBS = -lssl -lcrypto -lpthread

# 目標執行檔名稱
TARGET = client

# 源碼檔案
SRC = client.cpp

# 預設目標
all: $(TARGET)

# 編譯目標
$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LIBS)

# 清除編譯產生的檔案
clean:
	rm -f $(TARGET) *.o

# 声明伪目标
.PHONY: all clean
	