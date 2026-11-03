CXX ?= g++
CXXFLAGS = -std=c++17 -O3 -fPIC -Wall -Wextra

all: libmutator.so

libmutator.so: mutator_ext.cpp
	$(CXX) $(CXXFLAGS) -shared mutator_ext.cpp -o libmutator.so

clean:
	rm -f libmutator.so

.PHONY: all clean
