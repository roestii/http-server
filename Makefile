CFLAGS = 

ifeq ($(TLS), 1)
CFLAGS += -DTLS=1
CFLAGS += -lssl
endif 

ifeq ($(DEBUG_MODE), 1)
CFLAGS += -DDEBUG_MODE=1
CFLAGS += -g
endif


http_server: main.o http.o mem.o arena_allocator.o http_header_map.o string.o file_cache.o
	gcc $(CFLAGS) -o http_server main.o http.o mem.o arena_allocator.o http_header_map.o string.o file_cache.o

mem.o: src/mem.cpp src/mem.h src/types.h
	gcc $(CFLAGS) -c src/mem.cpp

worker_queue.o: src/worker_queue.cpp src/worker_queue.h src/types.h
	gcc $(CFLAGS) -c src/worker_queue.cpp

string.o: src/string.cpp src/string.h src/types.h
	gcc $(CFLAGS) -c src/string.cpp

file_cache.o: src/file_cache.cpp src/file_cache.h src/types.h
	gcc $(CFLAGS) -c src/file_cache.cpp

arena_allocator.o: src/arena_allocator.cpp src/arena_allocator.h src/types.h
	gcc $(CFLAGS) -c src/arena_allocator.cpp

stack_allocator.o: src/stack_allocator.cpp src/stack_allocator.h src/types.h
	gcc $(CFLAGS) -c src/stack_allocator.cpp

http_header_map.o: src/http_header_map.cpp src/http_header_map.h src/types.h src/mem.h
	gcc $(CFLAGS) -c src/http_header_map.cpp

http.o: src/http.cpp src/http.h src/mem.h src/types.h
	gcc $(CFLAGS) -c src/http.cpp 

main.o: src/main.cpp src/http.h src/types.h src/file_cache.h src/arena_allocator.h src/http_header_map.h
	gcc $(CFLAGS) -c src/main.cpp

clean:
	rm *.o http_server
