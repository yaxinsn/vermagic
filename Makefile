all:
	gcc vermagic.c -o vermagic -Wall -static

clean:
	rm vermagic
