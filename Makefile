
all:
	@mkdir -p bin/
	gcc -o bin/main main.c -luring -lssl -lcrypto -lpthread

t:
	@mkdir -p bin/
	@make
	./bin/main 8080
	