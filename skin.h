#ifndef SKIN_H
#define SKIN_H

#define PROG_NAME "skin"

#define debug_assert(b) {if(!(b)) {die(#b);}}
#define debug(...) {fprintf(stderr, __VA_ARGS__); fputc('\n', stderr);}
#define debug_named(...) debug(PROG_NAME": " __VA_ARGS__)
#define die(...) {debug_named(__VA_ARGS__); fputc('\n', stderr); exit(-1);}

#define min(a, b) (a < b ? a : b)
#define max(a, b) (a < b ? b : a)

#endif // SKIN_H
