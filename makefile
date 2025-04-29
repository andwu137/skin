FLAGS = -Wall -Wpedantic

all:
	$(CC) $(FLAGS) skin.c -o skin

clean:
	rm -f skin
