http_server: main.o http.o mem.o arena_allocator.o http_header_map.o
	gcc -g -o http_server main.o http.o mem.o arena_allocator.o http_header_map.o

mem.o: src/mem.cpp src/mem.h src/types.h
	gcc -g -c src/mem.cpp

arena_allocator.o: src/arena_allocator.cpp src/arena_allocator.h src/types.h
	gcc -g -c src/arena_allocator.cpp

http_header_map.o: src/http_header_map.cpp src/http_header_map.h src/types.h src/mem.h
	gcc -g -c src/http_header_map.cpp

http.o: src/http.cpp src/http.h src/mem.h src/types.h
	gcc -g -c src/http.cpp 

main.o: src/main.cpp src/http.h src/types.h src/arena_allocator.h src/http_header_map.h
	gcc -g -c src/main.cpp

clean:
	rm mem.o http.o main.o http_server
