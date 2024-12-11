http_server: main.o parser.o
	gcc -g -o http_server main.o parser.o

parser.o: src/parser.cpp src/parser.h src/types.h
	gcc -g -c src/parser.cpp

main.o: src/main.cpp src/parser.h src/types.h
	gcc -g -c src/main.cpp

clean:
	rm parser.o main.o http_server
