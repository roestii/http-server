http_server: main.o parser.o mem.o
	gcc -g -o http_server main.o parser.o mem.o

mem.o: src/mem.cpp src/mem.h src/types.h
	gcc -g -c src/mem.cpp

parser.o: src/parser.cpp src/parser.h src/mem.h src/types.h
	gcc -g -c src/parser.cpp 

main.o: src/main.cpp src/parser.h src/types.h
	gcc -g -c src/main.cpp

clean:
	rm mem.o parser.o main.o http_server
