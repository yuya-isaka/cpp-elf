CXX=g++
CXXFLAGS=-std=c++17 -Wall -Wextra -pedantic

all: elfreader

elfreader: main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^

test: elfreader
	./elfreader ./ctest/elfsamp.o
	./elfreader ./ctest/elfsamp

clean:
	rm -f elfreader
