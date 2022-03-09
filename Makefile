all:
	gcc client.c -ansi -pedantic -Wall -Wextra -std=c17 -o client

clean:
	-rm -fr client
