CC=g++
CFLAGS= -march=native 
LIB= -O3  
SOURCES= ELIMAC.cpp 
# SOURCES= MultCamp.cpp 
all: 
	$(CC) -o test $(SOURCES) $(LIB) $(CFLAGS) 
clean: 
	rm *.o 