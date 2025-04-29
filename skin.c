#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <linux/limits.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <spawn.h>
#endif

#include "array.c"
#include "skin_builtin.c"
#include "skin_lex.c"
#include "skin.h"

enum
{
    CREATE_PROCESS_BACKGROUND = 1 << 0,
};

enum execute_flag
{
    EXECUTE_CAPTURE_OUT = 1 << 0,
    EXECUTE_LPAREN = 1 << 1,
    EXECUTE_RPAREN = 1 << 2,
};

extern char **environ;

#define STDFD_NO_OVERRIDE ((struct stdfd){.in=-1, .out=-1, .err=-1});
struct stdfd
{
    int in;
    int out;
    int err;
};


char *
find_env(struct string_arr *envp, char *name, size_t name_size)
{
    array_null_foreach(envp, e)
    {
        if(strstr(*e, name) == *e) return *e + name_size + 1;
    }
    return NULL;
}

// WARN: create_process
// name must be null terminated
// args->buffer must be null terminated
// envp->buffer must be null terminated
pid_t
create_process(
        char *restrict name,
        struct string_arr *restrict args,
        struct string_arr *restrict envp,
        struct stdfd *restrict ofd,
        uint32_t flags)
{
    pid_t pid;
    posix_spawn_file_actions_t file_actions;

    debug_assert(name != NULL);
    debug_assert(args->buffer[args->size-1] == NULL);
    debug_assert(envp->buffer[envp->size-1] == NULL);

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
        char *p = find_env(envp, "PATH", sizeof("PATH") - 1);
        if(p == NULL) goto EXIT_FAIL;
        char *end = strchr(p, ':');
        /* NOTE: splits the PATH by ':'
         * replaces the ':' by '\0' before checking, reverts after the check
         * the tabbed in part is the check
         * WARN: posix says that directories cannot contain ':'
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
    return(0);

EXIT_CREATE:
    if(posix_spawn_file_actions_init(&file_actions))
        die("failed to init spawn file actions");

    if(ofd->out != -1 && posix_spawn_file_actions_adddup2(&file_actions, ofd->out, STDOUT_FILENO))
        die("failed to init spawn file actions file descriptor");
    if(ofd->in != -1 && posix_spawn_file_actions_adddup2(&file_actions, ofd->in, STDIN_FILENO))
        die("failed to init spawn file actions file descriptor");
    if(ofd->err != -1 && posix_spawn_file_actions_adddup2(&file_actions, ofd->err, STDERR_FILENO))
        die("failed to init spawn file actions file descriptor");

    if(posix_spawn(&pid, binary, &file_actions, NULL, args->buffer, envp->buffer) || pid == -1)
        die("failed to spawn child");
    if(posix_spawn_file_actions_destroy(&file_actions)) die("failed to destroy spawn file actions");

    if(flags & CREATE_PROCESS_BACKGROUND)
    {
        return(pid);
    }
    else
    {
        waitpid(pid, NULL, 0);
        return(0);
    }
}

int
execute(
        struct lex_state *restrict ls,
        struct string_arr *restrict envp,
        char **restrict output,
        uint32_t flags)
{
    int retval = 0;
    int64_t res;
    struct string temp_str = {0};

    /* fork prep */
    struct string_arr args = {0};
    array_init(&args, 8);

    struct string name = {0};
    array_init(&name, 8);

    uint32_t child_flags = 0;
    struct stdfd ov_stdfd = STDFD_NO_OVERRIDE;
    int pipefd[2];

    /* parse */
    res = lex_next(ls, &name);
    if(flags & EXECUTE_LPAREN) { if(res != TOKEN_LPAREN) {retval = -1; goto EXIT;} }

    // name
    if(res == TOKEN_LPAREN) res = lex_next(ls, &name);
    if(res != TOKEN_IDENT && res != TOKEN_STRING) {retval = -1; goto EXIT;}
    array_push(&name, '\0');
    array_push(&args, name.buffer);

    // args
    array_init(&temp_str, 8);
    while(1)
    {
        res = lex_next(ls, &temp_str);
        if(res == TOKEN_STRING || res == TOKEN_IDENT)
        {
            array_push(&temp_str, '\0');
            array_push(&args, temp_str.buffer);
            array_init(&temp_str, 8);
        }
        else if(res == TOKEN_LPAREN)
        {
            array_push(&args, NULL);
            if(execute(ls, envp, &args.buffer[args.size - 1],
                        EXECUTE_CAPTURE_OUT | EXECUTE_RPAREN) == -1)
            {
                retval = -1; goto EXIT;
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
    size_t num_args = args.size - 2;
    if(strcmp(name.buffer, "cd") == 0)
    {
        char *path = NULL;
        if(num_args == 0) path = builtin_home;
        else if(num_args == 1) path = args.buffer[1];
        else {debug_named("cd: requires 0 or 1 arguments"); retval = -1; goto EXIT;}
        builtin_cd(path, envp->buffer);
        goto EXIT;
    }
    else if(strcmp(name.buffer, "getcwd") == 0)
    {
        if(flags & EXECUTE_CAPTURE_OUT) *output = strdup(builtin_cwd);
        else printf("%s", builtin_cwd);
        goto EXIT;
    }
    else if(strcmp(name.buffer, "getenv") == 0)
    {
        if(num_args == 0) {debug_named("cd: requires >0 arguments"); retval = -1; goto EXIT;}
        if(flags & EXECUTE_CAPTURE_OUT)
        {
            array_init(&temp_str, num_args * 16);
        }

        array_null_foreach_offset(&args, 1, x)
        {
            char *p = find_env(envp, *x, strlen(*x));
            if(p != NULL)
            {
                if(flags & EXECUTE_CAPTURE_OUT) { array_concat(&temp_str, p, strlen(p)); }
                else puts(p);
            }
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
        goto EXIT;
    }
    else if(strcmp(name.buffer, "pipe") == 0)
    {
        goto EXIT;
    }
    else if(strcmp(name.buffer, "exit") == 0)
    {
        exit(0);
    }

    // prep child
    if(flags & EXECUTE_CAPTURE_OUT)
    {
        if(pipe(pipefd) == -1) die("failed to spawn pipe");
        ov_stdfd.out = pipefd[1];
        child_flags |= CREATE_PROCESS_BACKGROUND;
    }

    // spawn
    pid_t pid = create_process(name.buffer, &args, envp, &ov_stdfd, child_flags);

    // post child
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
        if(close(pipefd[0]) == -1) die("failed to close pipefd");
        waitpid(pid, NULL, 0);

        buf.buffer[buf.size - 1] = '\0';
        *output = buf.buffer;
    }

EXIT:
    /* clean */
    array_clear(array_null_foreach, &args);
    array_destroy(&args);
    return(retval);
}

ssize_t
read_line(
        char *restrict prompt,
        size_t prompt_size,
        char **restrict line,
        size_t *restrict size,
        struct string_arr *restrict envp,
        FILE *restrict in,
        FILE *restrict out)
{
    struct lex_state ls = {0};
    lex_init(&ls, prompt, prompt_size);
    execute(&ls, envp, NULL, 0);
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
    char shell_path[PATH_MAX + sizeof("SHELL=")] = "SHELL=";
    realpath(argv[0], shell_path + sizeof("SHELL=") - 1);

    struct string_arr envp = {0};
    {
        array_init(&envp, 16);
        char **e = environ;
        while(*e != NULL) {
            if(strstr(*e, "HOME") == *e) strncpy(builtin_home, *e + sizeof("HOME"), PATH_MAX);
            if(strstr(*e, "SHELL") == *e) { array_push(&envp, shell_path); }
            else array_push(&envp, *e);
            e++;
        }
        array_push(&envp, NULL);
    }

    if (getcwd(builtin_cwd, sizeof(builtin_cwd)) == NULL) die("unable to get cwd");

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

    // // DEBUG: static tests
    // char temp_buf[] = "(echo '(hi \\(lmao\\) \"bro\") (date -I) (echo kjfd) klsjdflkjdsal)";
    // lex_init(&ls, temp_buf, sizeof(temp_buf));
    // debug_named("retval: %d", execute(&ls, &envp, NULL, 0));

    char *line = NULL;
    size_t line_size = 0;
    while(read_line(prompt, prompt_size, &line, &line_size, &envp, stdin, stdout) != -1)
    {
        lex_init(&ls, line, line_size);
        execute(&ls, &envp, NULL, 0);
        // debug_named("retval: %d", execute(&ls, &envp, NULL, 0));
    }
    free(line);
    array_destroy(&envp);

    return(0);
}
