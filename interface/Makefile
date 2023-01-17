all : app

app : interface.o

interface.o : interface.c 
	gcc -Wall -I/usr/local/lib interface.c -o interface.o -ldl -g

clean:
	rm -rf interface.o