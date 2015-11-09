all: hw3

hw3: hw3.c table.c table.h
	gcc -Wall -ggdb -o hw3 hw3.c table.c -lpcap 

clean:
	rm -rf *.o hw3
