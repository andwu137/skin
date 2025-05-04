#ifndef SKIN_LEX_C
#define SKIN_LEX_C

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "array.c"
#include "skin.h"

enum token_t
{
    TOKEN_ERROR = -1,
    TOKEN_EOF = 0,
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_IDENT,
    TOKEN_STRING,
};

struct lex_state
{
    char *line;
    size_t line_size;
    size_t line_pos;
};

void
lex_init(
        struct lex_state *restrict ls,
        char *restrict buf,
        size_t buf_size)
{
    ls->line = buf;
    ls->line_size = buf_size;
    ls->line_pos = 0;
}

int
lex_next_pos(struct lex_state *restrict ls)
{
    if(++ls->line_pos < ls->line_size) return(1);
    else return(0);
}

uint8_t
lex_isfinished(struct lex_state *restrict ls)
{
    return(ls->line_size <= ls->line_pos);
}

uint8_t
isident(char c)
{
    return(isalpha(c)
        || isdigit(c)
        || (ispunct(c)
                && c != '#'
                && c != '"'
                && c != '\''
                && c != '('
                && c != ')'));
}

// TODO: escape codes
int64_t
lex_next(struct lex_state *restrict ls, struct string *lex_raw)
{
    if(lex_raw != NULL)
    {
        memset(lex_raw->buffer, 0, lex_raw->capacity);
        lex_raw->size = 0;
    }

    if(ls->line_pos < ls->line_size)
    {
        while(1)
        {
            if(ls->line[ls->line_pos] == '#') // comment
            {
                lex_next_pos(ls);
                while(ls->line[ls->line_pos] != '#') { if (!lex_next_pos(ls)) return(TOKEN_EOF); }
            }
            else if(isspace(ls->line[ls->line_pos])) {}
            else break;

            if (!lex_next_pos(ls)) return(TOKEN_EOF);
        }

        if(ls->line[ls->line_pos] == '(')
        {
            lex_next_pos(ls);
            return(TOKEN_LPAREN);
        }
        else if(ls->line[ls->line_pos] == ')')
        {
            lex_next_pos(ls);
            return(TOKEN_RPAREN);
        }
        else if(lex_raw != NULL)
        {
            // TODO: numbers
            if(isident(ls->line[ls->line_pos])) // ident
            {
                array_push(lex_raw, ls->line[ls->line_pos]);
                while(lex_next_pos(ls) && isident(ls->line[ls->line_pos]))
                {
                    array_push(lex_raw, ls->line[ls->line_pos]);
                }
                return(TOKEN_IDENT);
            }
            else if(ls->line[ls->line_pos] == '\'') // string
            {
                lex_next_pos(ls);
                if(ls->line[ls->line_pos] != '(') return(TOKEN_ERROR);
                lex_next_pos(ls);
                while(1) // TODO: redesign the strings
                {
                    if(ls->line[ls->line_pos] == ')')
                    {
                        lex_next_pos(ls);
                        return(TOKEN_STRING);
                    }
                    else if(ls->line_pos + 1 < ls->line_size
                        && ls->line[ls->line_pos] == '\\')
                    {
                        switch(ls->line[ls->line_pos + 1])
                        {
                        case '(': { array_push(lex_raw, '('); } break;
                        case ')': { array_push(lex_raw, ')'); } break;
                        case '\\': { array_push(lex_raw, '\\'); } break;
                        case 'n': { array_push(lex_raw, '\n'); } break;
                        case 't': { array_push(lex_raw, '\t'); } break;
                        default: {
                            array_push(lex_raw, ls->line[ls->line_pos]);
                            array_push(lex_raw, ls->line[ls->line_pos + 1]);
                        } break;
                        }
                        lex_next_pos(ls);
                        lex_next_pos(ls);
                    }
                    else
                    {
                        array_push(lex_raw, ls->line[ls->line_pos]);
                        if (!lex_next_pos(ls)) return(TOKEN_EOF);
                    }
                }
            }
        }
    }

    if(ls->line_pos + 1 < ls->line_size) return(TOKEN_ERROR);

    ls->line_pos++;
    return(TOKEN_EOF);
}

#endif // SKIN_LEX_C
