CXX = g++
CXXFLAGS = -Wall -Wextra -O2 -std=c++17
LDLIBS = -lpcap
TARGET = tls-block
SRCS = main.cpp

all: $(TARGET)

$(TARGET): $(SRCS) ansheader.h
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
