CXXFLAGS=-std=c++17

default: parser

block.o: block.hpp block.cpp

hasher.o: hasher.hpp hasher.cpp

string_utils.o: string_utils.hpp string_utils.cpp

parser: block.o hasher.o string_utils.o parser.cpp

.PHONY: clean

clean:
	rm -rf parser *.o
