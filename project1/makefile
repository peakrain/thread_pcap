OBJ=main.o packet.o thread.o
LIB=-lpcap -lpthread
main:main.o packet.o thread.o
	gcc -o main ${OBJ} ${LIB}
clean:
	rm -f ${OBJ}

