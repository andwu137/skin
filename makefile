FLAGS = -Wall -Wpedantic

all:
	$(CC) $(FLAGS) skin.c -o skin

debug:
	$(CC) -DDEBUG=1 -g $(FLAGS) skin.c -o skin

clean:
	rm -f skin
