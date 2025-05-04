#include <glob.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wordexp.h>

#if defined(__linux__)
#include <linux/limits.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <spawn.h>
#endif

#include "array.c"
#include "skin_lex.c"
#include "skin.h"

/* EXTERNALS */
extern char **environ;

/* TYPES */
struct pipefd_t
{
    int pipefd[2];
};

enum execute_flag
{
    EXECUTE_LPAREN = 1 << 0,
    EXECUTE_RPAREN = 1 << 1,
    EXECUTE_CAPTURE_OUT = 1 << 2,
    EXECUTE_BACKGROUND = 1 << 3,
};

#define STDFD_NO_OVERRIDE_BASE {.in=-1, .out=-1, .err=-1, .close = NULL}
#define STDFD_NO_OVERRIDE ((struct stdfd)STDFD_NO_OVERRIDE_BASE)
struct stdfd
{
    int in;
    int out;
    int err;
    int *close;
    size_t close_size;
};

/* GLOBALS */
struct stdfd const _no_override_stdfd = STDFD_NO_OVERRIDE_BASE;

char _skin_cwd[PATH_MAX] = {0};
char *_skin_home = NULL;

pid_t _skin_fg = 0;
int _skin_return_code = 0;
uint8_t _skin_exit = 0;

/* UTILS */
void
trim_end(char *restrict arr, size_t arr_size, char e)
{
    for(size_t i = arr_size - 1; i >= 0; i--)
    {
        if(arr[i] == e) arr[i] = '\0';
        else break;
    }
}

/* PROCESSES */
// WARN: create_process_bg
// name must be null terminated
// args->buffer must be null terminated
pid_t
create_process_bg(
        char const *restrict name,
        struct string_arr const *restrict args,
        struct stdfd ofd)
{
    pid_t pid;
    posix_spawn_file_actions_t file_actions;

    debug_assert(name != NULL);
    debug_assert(array_end_idx(args, -1) == NULL);

    char binary[PATH_MAX] = {0};
    struct stat bin_stat;
    char *last_cpy;

    if(name[0] == '.') // find as relative
    {
        realpath(name, binary);
        if(stat(binary, &bin_stat) == 0
                && (bin_stat.st_mode & S_IFMT) == S_IFREG)
        {
            goto EXIT_CREATE;
        }
    }
    else // find in PATH
    {
        char *p = getenv("PATH");
        if(p == NULL) goto EXIT_FAIL;
        char *end = strchr(p, ':');
        /* NOTE: splits the PATH by ':'
         * replaces the ':' by '\0' before checking, reverts after the check
         * the tabbed in part is the check
         * NOTE: posix says that directories cannot contain ':'
         */
        while(end != NULL)
        {
            *end = '\0';
                memset(binary, 0, PATH_MAX);
                last_cpy = strncpy(binary, p, PATH_MAX);
                last_cpy = strncat(last_cpy, "/", PATH_MAX - (last_cpy - binary));
                strncat(last_cpy, name, PATH_MAX - (last_cpy - binary));
                if(stat(binary, &bin_stat) == 0
                        && (bin_stat.st_mode & S_IFMT) == S_IFREG)
                {
                    *end = ':';
                    goto EXIT_CREATE;
                }
            *end = ':';
            p = end + 1;
            end = strchr(p, ':');
        }
    }

EXIT_FAIL:
    // failure
    debug_named("failed to find binary: '%s'", name);
    return(-1);

EXIT_CREATE:
    if(posix_spawn_file_actions_init(&file_actions))
        die("failed to init spawn file actions");

    if(ofd.out != -1 && posix_spawn_file_actions_adddup2(&file_actions, ofd.out, STDOUT_FILENO))
        die("failed to init spawn file actions");
    if(ofd.in != -1 && posix_spawn_file_actions_adddup2(&file_actions, ofd.in, STDIN_FILENO))
        die("failed to init spawn file actions");
    if(ofd.err != -1 && posix_spawn_file_actions_adddup2(&file_actions, ofd.err, STDERR_FILENO))
        die("failed to init spawn file actions");

    for(size_t i = 0; i < ofd.close_size; i++)
    {
        if(ofd.close[i] != -1 && posix_spawn_file_actions_addclose(&file_actions, ofd.close[i]))
            die("failed to init spawn file actions");
    }

    if(posix_spawn(&pid, binary, &file_actions, NULL, args->buffer, environ) || pid == -1)
        die("failed to spawn child");
    if(posix_spawn_file_actions_destroy(&file_actions)) die("failed to destroy spawn file actions");

    return(pid);
}

pid_t
create_process_fg(
        char const *restrict name,
        struct string_arr const *restrict args,
        struct stdfd ofd)
{
    pid_t pid = create_process_bg(name, args, ofd);
    if(pid == -1)
    {
        return -1;
    }
    else
    {
        _skin_fg = pid;
        return waitpid(pid, NULL, 0);
    }
}

/* MAIN */
void
execute_pre_capture_out(int *pipefd, struct stdfd *ov_stdfd)
{
    if(pipe(pipefd) == -1) die("failed to spawn pipe");
    ov_stdfd->out = pipefd[1];
}

// TODO: add bg processes to a stack
int
execute(
        struct lex_state *restrict ls,
        struct stdfd ov_stdfd,
        char **restrict output,
        uint32_t flags)
{
    pid_t pid = -1;
    int retval = 0;
    int64_t res;
    struct string temp_str = {0};

    /* spawn prep */
    struct string_arr args = {0};
    array_init(&args, 8);

    struct string name = {0};
    array_init(&name, 8);
    array_push(&args, name.buffer);

    int pipefd[2];

    /* parse */
    res = lex_next(ls, &name); // TODO: allow macros
    if(res == TOKEN_EOF) {retval = 0; goto EXIT;}
    if(flags & EXECUTE_LPAREN) {if(res != TOKEN_LPAREN) {retval = -1; goto EXIT;}}

    // name
    if(res == TOKEN_LPAREN) res = lex_next(ls, &name);
    if(res != TOKEN_IDENT && res != TOKEN_STRING) {retval = -1; goto EXIT;}
    array_push(&name, '\0');
    array_end_idx(&args, -1) = name.buffer;

    // args
    array_init(&temp_str, 8);
    while(1)
    {
        res = lex_next(ls, &temp_str);
        // TODO: numbers
        if(res == TOKEN_STRING || res == TOKEN_IDENT)
        {
            array_push(&temp_str, '\0');
            array_push(&args, temp_str.buffer);
            array_init(&temp_str, 8);
        }
        else if(res == TOKEN_LPAREN)
        {
            array_push(&args, NULL);
            if(execute(ls, _no_override_stdfd, &array_end_idx(&args, -1),
                        EXECUTE_CAPTURE_OUT | EXECUTE_RPAREN) == -1)
            {
                retval = -1;
                goto EXIT;
            }
        }
        else
        {
            break;
        }
    }
    array_destroy(&temp_str);
    array_push(&args, NULL);

    if(flags & EXECUTE_RPAREN && res != TOKEN_RPAREN) {retval = -1; goto EXIT;}

    /* finish */
    // builtin checks
    // TODO: create_process for pipe
    size_t num_args = args.size - 2;
    if(strcmp(name.buffer, "cd") == 0)
    {
        uint8_t alloc_string = 0;
        char *dir = NULL;
        if(num_args == 0) {dir = _skin_home;}
        else if(num_args == 1)
        {
            dir = args.buffer[1];
            trim_end(dir, strlen(dir), '\n');
        }
        else
        {
            alloc_string = 1;
            array_init(&temp_str, num_args * 8);
            array_null_foreach_offset(&args, 1, x)
            {
                array_concat(&temp_str, *x, strlen(*x));
            }
            array_push(&temp_str, '\0');
            dir = temp_str.buffer;
        }

        if (dir == NULL) {retval = -1; goto BUILTIN_CD_EXIT;}

        char cwd[PATH_MAX] = {0};
        if(realpath(dir, cwd) == NULL) {debug_named("cd: failed to resolve path"); retval = -1; goto BUILTIN_CD_EXIT;}

        struct stat file_stat;
        if (stat(cwd, &file_stat) == 0 && (file_stat.st_mode & S_IFMT) == S_IFDIR)
        {
            strncpy(_skin_cwd, cwd, PATH_MAX);
            chdir(_skin_cwd);
            retval = setenv("PWD", _skin_cwd, 1);
        }
        else
        {
            debug_named("directory does not exist\n");
            retval = -1;
        }

BUILTIN_CD_EXIT:
        if(alloc_string && dir != NULL) free(dir);
        goto EXIT;
    }
    else if(strcmp(name.buffer, "gethome") == 0 || strcmp(name.buffer, "~") == 0)
    {
        if(flags & EXECUTE_CAPTURE_OUT) *output = strdup(_skin_home);
        else puts(_skin_home);
        goto EXIT;
    }
    else if(strcmp(name.buffer, "getcwd") == 0)
    {
        if(flags & EXECUTE_CAPTURE_OUT) *output = strdup(_skin_cwd);
        else puts(_skin_cwd);
        goto EXIT;
    }
    else if(strcmp(name.buffer, "getenv") == 0)
    {
        if(num_args == 0) {debug_named("getenv: requires >0 arguments"); retval = -1; goto EXIT;}

        if(flags & EXECUTE_CAPTURE_OUT) {array_init(&temp_str, num_args * 16);}

        uint8_t one_not_found = 0;
        array_null_foreach_offset(&args, 1, x)
        {
            char *p = getenv(*x);
            if(p == NULL)
            {
                one_not_found = 1;
            }
            else
            {
                if(flags & EXECUTE_CAPTURE_OUT) {array_concat(&temp_str, p, strlen(p));}
                else puts(p);
                break;
            }
        }
        if(one_not_found) retval = -1;

        if(flags & EXECUTE_CAPTURE_OUT)
        {
            array_push(&temp_str, '\0');
            *output = temp_str.buffer;
        }
        goto EXIT;
    }
    else if(strcmp(name.buffer, "realpath") == 0)
    {
        if(num_args == 0) {debug_named("realpath: requires >0 arguments"); retval = -1; goto EXIT;}

        if(flags & EXECUTE_CAPTURE_OUT) {array_init(&temp_str, PATH_MAX);}

        array_null_foreach_offset(&args, 1, a)
        {
            if(flags & EXECUTE_CAPTURE_OUT)
            {
                size_t old_size = temp_str.size;
                temp_str.size += PATH_MAX - (temp_str.capacity - temp_str.size);
                array_resize(&temp_str);
                if(realpath(*a, &temp_str.buffer[old_size]) == NULL) {debug_named("realpath: failed to resolve path"); retval = -1; goto EXIT;}
            }
            else
            {
                char temp_str[PATH_MAX] = {0};
                if(realpath(*a, temp_str) == NULL) {debug_named("realpath: failed to resolve path"); retval = -1; goto EXIT;}
                puts(temp_str);
            }
        }

        if(flags & EXECUTE_CAPTURE_OUT)
        {
            array_push(&temp_str, '\0');
            *output = temp_str.buffer;
        }
        goto EXIT;
    }
    else if(strcmp(name.buffer, "glob") == 0)
    {
        if(num_args == 0) {debug_named("glob: requires >0 arguments"); retval = -1; goto EXIT;}

        if(flags & EXECUTE_CAPTURE_OUT) {array_init(&temp_str, 128);}

        glob_t pglob = {0};
        memset(&pglob, 0, sizeof(pglob));

        array_null_foreach_offset(&args, 1, a)
        {
            if(glob(*a, 0, NULL, &pglob) != 0) {debug_named("glob: failed to glob directory"); retval = -1; goto EXIT;}
            for(size_t i = 0; i < pglob.gl_pathc; i++)
            {
                if(flags & EXECUTE_CAPTURE_OUT)
                {
                    array_concat(&temp_str, pglob.gl_pathv[i], strlen(pglob.gl_pathv[i]));
                    array_push(&temp_str, '\n'); // TODO: allow for null-sep
                }
                else
                {
                    puts(pglob.gl_pathv[i]);
                }
            }
            globfree(&pglob);
        }

        if(flags & EXECUTE_CAPTURE_OUT)
        {
            array_push(&temp_str, '\0');
            *output = temp_str.buffer;
        }
        goto EXIT;
    }
    else if(strcmp(name.buffer, "setenv") == 0)
    {
        if(num_args < 2 || num_args % 2 != 0) {debug_named("setenv: requires x>=2 && iseven(x) arguments"); retval = -1; goto EXIT;}
        array_null_foreach_offset(&args, 1, a)
        {
            if(setenv(*a, *(a + 1), 1) == -1) retval = -1;
            a++;
        }
        goto EXIT;
    }
    else if(strcmp(name.buffer, "unsetenv") == 0)
    {
        if(num_args < 1) {debug_named("unsetenv: requires >=1 argument"); retval = -1; goto EXIT;}
        array_null_foreach_offset(&args, 1, a)
        {
            if(unsetenv(*a) == -1) retval = -1;
        }
        goto EXIT;
    }
    else if(strcmp(name.buffer, "redirect") == 0)
    {
        if(num_args != 3) {debug_named("redirect: requires 3 arguments"); retval = -1; goto EXIT;}
        uint8_t found = 0;
        mode_t mode = S_IRUSR|S_IWUSR|S_IRGRP;
        if(strcmp(args.buffer[1], "in") == 0)
        {
            found = 1;
            ov_stdfd.in = open(args.buffer[2], O_RDONLY);
        }
        else if(strcmp(args.buffer[1], "out") == 0)
        {
            found = 1;
            ov_stdfd.out = open(args.buffer[2], O_WRONLY|O_CREAT|O_TRUNC, mode);
        }
        else if(strcmp(args.buffer[1], "append") == 0)
        {
            found = 1;
            ov_stdfd.out = open(args.buffer[2], O_WRONLY|O_CREAT|O_APPEND, mode);
        }

        if(ov_stdfd.out == -1) {debug_named("redirect: could not open file"); retval = -1; goto EXIT;}
        if(!found) retval = -1;

        lex_init(ls, args.buffer[3], strlen(args.buffer[3]));
        retval = execute(ls, ov_stdfd, output, flags);
        goto EXIT;
    }
    else if(strcmp(name.buffer, "pipe") == 0 || strcmp(name.buffer, "|") == 0)
    {
        if(num_args < 2) {debug_named("pipe: requires >=2 arguments"); retval = -1; goto EXIT;}

        struct pipefd_t *pipefd_arr = calloc(num_args - 1, sizeof(*pipefd_arr));
        if(pipefd_arr == NULL) die("failed to alloc");

        pid_t *pid_arr = calloc(num_args, sizeof(*pid_arr));
        if(pid_arr == NULL) die("failed to alloc");

        struct stdfd new_ov_stdfd = ov_stdfd;
        new_ov_stdfd.close = (int *)pipefd_arr; // WARN: we ignore the ov_stdfd.close
        new_ov_stdfd.close_size = 0;
        int temp_fds[2] = {0};

        for(size_t i = 0; i < num_args; i++)
        {
            // pipe
            if(i != num_args - 1 && pipe(pipefd_arr[i].pipefd) == -1) die("pipe: failed to create");

            if(i != num_args - 1)
            {
                new_ov_stdfd.out = pipefd_arr[i].pipefd[1];
                // disable close
                temp_fds[1] = pipefd_arr[i].pipefd[1];
                pipefd_arr[i].pipefd[1] = -1;
            }
            else
            {
                if(flags & EXECUTE_CAPTURE_OUT) execute_pre_capture_out(pipefd, &new_ov_stdfd);
                else new_ov_stdfd.out = ov_stdfd.out;
            }

            if(i != 0)
            {
                new_ov_stdfd.in = pipefd_arr[i - 1].pipefd[0];
                // disable close
                temp_fds[0] = pipefd_arr[i - 1].pipefd[0];
                pipefd_arr[i - 1].pipefd[0] = -1;
            }
            else
            {
                new_ov_stdfd.in = ov_stdfd.in;
            }

            // setup the close array
            new_ov_stdfd.close_size =
                (i == num_args - 1)
                ? (i * 2)
                : ((i + 1) * 2);

            // WARN: spawn
            // multiple executes in a row, works because:
            // - execute's lexing is synchronous
            // - new_ov_stdfd is copied
            // - close gets used immediately when executing
            struct lex_state ls2 = {0};
            lex_init(&ls2, args.buffer[i + 1], strlen(args.buffer[i + 1]));
            pid_arr[i] = execute(&ls2, new_ov_stdfd, NULL, EXECUTE_BACKGROUND);
            if(pid_arr[i] == -1) {die("failed to pipe");} // TODO: better resolve

            // reset pipefd_arr to original state
            if(i != 0) pipefd_arr[i - 1].pipefd[0] = temp_fds[0];
            if(i != num_args - 1) pipefd_arr[i].pipefd[1] = temp_fds[1];
        }

        // cleanup
        for(size_t i = 0; i < num_args - 1; i++)
        {
            close(pipefd_arr[i].pipefd[0]);
            close(pipefd_arr[i].pipefd[1]);
            if((retval = waitpid(pid_arr[i], NULL, 0)) == -1) goto EXIT;
        }

        retval = 0;
        if((flags & (EXECUTE_CAPTURE_OUT | EXECUTE_BACKGROUND)) == 0)
            retval = waitpid(pid_arr[num_args - 1], NULL, 0);
        else retval = pid = pid_arr[num_args - 1];

        free(pipefd_arr);
        free(pid_arr);
        if(flags & EXECUTE_CAPTURE_OUT) goto EXIT_POST_CHILD;
        else goto EXIT;
    }
    else if(strcmp(name.buffer, "exit") == 0)
    {
        pid_t process_ret;
        do
        {
            // TODO: kill children
            process_ret = wait(NULL);
        } while(process_ret != -1);
        _skin_exit = 1;
        goto EXIT;
    }
    else if(strcmp(name.buffer, "concat") == 0 || strcmp(name.buffer, "<>") == 0)
    {
        if(flags & EXECUTE_CAPTURE_OUT) {array_init(&temp_str, num_args * 8);}

        array_null_foreach_offset(&args, 1, x)
        {
            if(flags & EXECUTE_CAPTURE_OUT) {array_concat(&temp_str, *x, strlen(*x));}
            else printf("%s", *x);
        }

        if(flags & EXECUTE_CAPTURE_OUT)
        {
            array_concat(&temp_str, "\n", sizeof("\n"));
            *output = temp_str.buffer;
        }
        else putchar('\n');
        goto EXIT;
    }

    // prep child
    if(flags & EXECUTE_CAPTURE_OUT) execute_pre_capture_out(pipefd, &ov_stdfd);

    // spawn
    if(flags & EXECUTE_CAPTURE_OUT) pid = create_process_bg(name.buffer, &args, ov_stdfd);
    else if(flags & EXECUTE_BACKGROUND) retval = pid = create_process_bg(name.buffer, &args, ov_stdfd);
    else retval = pid = create_process_fg(name.buffer, &args, ov_stdfd);

    // post child
EXIT_POST_CHILD:
    if(flags & EXECUTE_CAPTURE_OUT)
    {
        if(close(pipefd[1]) == -1) die("failed to close pipefd");

        struct string buf = {0};
        array_init(&buf, 128);
        size_t read_size;
        while ((read_size = read(pipefd[0], buf.buffer + buf.size, buf.capacity - buf.size)) > 0)
        {
            buf.size += read_size;
            array_resize(&buf);
        }
        if(pipefd[0] != -1 && close(pipefd[0]) == -1) die("failed to close pipefd");
        retval = waitpid(pid, NULL, 0);

        buf.buffer[buf.size - 1] = '\0';
        *output = buf.buffer;
    }

EXIT:
    /* clean */
    array_clear(array_null_foreach, &args);
    array_destroy(&args);
    return(retval < 0 ? retval : 0);
}

ssize_t
read_line(
        char *restrict prompt,
        size_t prompt_size,
        char **restrict line,
        size_t *restrict size,
        FILE *restrict in,
        FILE *restrict out)
{
    struct lex_state ls = {0};
    lex_init(&ls, prompt, prompt_size);
    execute(&ls, _no_override_stdfd, NULL, 0);
    fflush(out);
    return(getline(line, size, in));
}

void
signal_handler(int sig_num)
{
    if(sig_num == SIGINT)
    {
        // TODO: if process is fg, then send SIGINT
    }
}

int
main(int argc, char **argv)
{
    /* vars */
    char shell_path[PATH_MAX] = {0};
    realpath(argv[0], shell_path);
    setenv("SHELL", shell_path, 1);

    if (getcwd(_skin_cwd, sizeof(_skin_cwd)) == NULL) die("unable to get cwd");
    if ((_skin_home = getenv("HOME")) == NULL) die("unable to get home");

    char *prompt = "(printf '(\\n%s\\n$ ) (getcwd))";
    size_t prompt_size = strlen(prompt);

    /* signals */
    struct sigaction signal_handler_struct;
    {
        memset (&signal_handler_struct, 0, sizeof(signal_handler_struct));
        signal_handler_struct.sa_handler = signal_handler;
        signal_handler_struct.sa_flags = SA_RESTART;

        if (sigaction(SIGINT, &signal_handler_struct, NULL)) die("failed to register SIGINT handler");
    }

    /* main */
    struct lex_state ls = {0};

#if DEBUG
{
    int retval = 0;
    char *output = NULL;
    char temp_lines[][256] = {
        "echo hi",
        "| ls '(xargs echo)"
    };
    uint32_t flags[] = {
        0, EXECUTE_CAPTURE_OUT, EXECUTE_BACKGROUND,
        EXECUTE_CAPTURE_OUT | EXECUTE_BACKGROUND
    };
    for(size_t i = 0;
        i < sizeof(temp_lines) / sizeof(*temp_lines);
        i++)
    {
        puts("\n>>>>>> NEW TEST TYPE");
        for(size_t j = 0;
            j < sizeof(flags) / sizeof(*flags);
            j++)
        {
            puts("\n>>> NEW TEST");
            lex_init(&ls, temp_lines[i], sizeof(temp_lines[i]));
            retval = execute(&ls, _no_override_stdfd, &output, flags[j]);
            debug_named("[retval: %d %s]", retval, output);
            if(retval > 0) waitpid(retval, NULL, 0);
            if(flags[j] & EXECUTE_CAPTURE_OUT) {free(output); output = NULL;}
            printf("push: "); fflush(stdout); getchar();
        }
    }
}
#endif

    char *line = NULL;
    size_t line_size = 0;
    size_t line_capacity = 0;
    while(!_skin_exit
            && (line_size = read_line(prompt, prompt_size, &line, &line_capacity, stdin, stdout)) != -1)
    {
        lex_init(&ls, line, line_size - 1);
        do
        {
            _skin_return_code = execute(&ls, _no_override_stdfd, NULL, 0);
            debug_named("retval: %d", _skin_return_code);
        } while(!lex_isfinished(&ls));
    }
    free(line);

    return(0);
}
