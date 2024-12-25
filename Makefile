http_server: main.o http.o mem.o arena_allocator.o http_header_map.o string.o file_cache.o
ifdef DEBUG_MODE
	gcc -DDEBUG_MODE=1 -g -o http_server main.o http.o mem.o arena_allocator.o http_header_map.o string.o file_cache.o
else
	gcc -o http_server main.o http.o mem.o arena_allocator.o http_header_map.o string.o file_cache.o
endif

mem.o: src/mem.cpp src/mem.h src/types.h
ifdef DEBUG_MODE
	gcc -DDEBUG_MODE=1 -g -c src/mem.cpp
else
	gcc -c src/mem.cpp
endif

worker_queue.o: src/worker_queue.cpp src/worker_queue.h src/types.h
ifdef DEBUG_MODE
	gcc -DDEBUG_MODE=1 -g -c src/worker_queue.cpp
else
	gcc -c src/worker_queue.cpp
endif

string.o: src/string.cpp src/string.h src/types.h
ifdef DEBUG_MODE
	gcc -DDEBUG_MODE=1 -g -c src/string.cpp
else
	gcc -c src/string.cpp
endif

file_cache.o: src/file_cache.cpp src/file_cache.h src/types.h
ifdef DEBUG_MODE
	gcc -DDEBUG_MODE=1 -g -c src/file_cache.cpp
else
	gcc -c src/file_cache.cpp
endif

arena_allocator.o: src/arena_allocator.cpp src/arena_allocator.h src/types.h
ifdef DEBUG_MODE
	gcc -DDEBUG_MODE=1 -g -c src/arena_allocator.cpp
else
	gcc -c src/arena_allocator.cpp
endif

stack_allocator.o: src/stack_allocator.cpp src/stack_allocator.h src/types.h
ifdef DEBUG_MODE
	gcc -DDEBUG_MODE=1 -g -c src/stack_allocator.cpp
else
	gcc -c src/stack_allocator.cpp
endif

http_header_map.o: src/http_header_map.cpp src/http_header_map.h src/types.h src/mem.h
ifdef DEBUG_MODE
	gcc -DDEBUG_MODE=1 -g -c src/http_header_map.cpp
else
	gcc -c src/http_header_map.cpp
endif

http.o: src/http.cpp src/http.h src/mem.h src/types.h
ifdef DEBUG_MODE
	gcc -DDEBUG_MODE=1 -g -c src/http.cpp 
else
	gcc -c src/http.cpp
endif

main.o: src/main.cpp src/http.h src/types.h src/file_cache.h src/arena_allocator.h src/http_header_map.h
ifdef DEBUG_MODE
	gcc -DDEBUG_MODE=1 -g -c src/main.cpp
else
	gcc -c src/main.cpp
endif

clean:
	rm *.o http_server
