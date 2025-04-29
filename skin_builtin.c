#ifndef SKIN_BUILTIN_C
#define SKIN_BUILTIN_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__)
#include <linux/limits.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

char builtin_cwd[PATH_MAX];
char builtin_home[PATH_MAX];

void
builtin_cd(
        char *restrict dir,
        char **restrict envp)
{
    if (dir == NULL) return;

    char cwd[PATH_MAX] = {0};
    if (dir[0] == '/') strncpy(cwd, dir, PATH_MAX);
    else realpath(dir, cwd);

    struct stat file_stat;
    if (stat(cwd, &file_stat) == 0 && (file_stat.st_mode & S_IFMT) == S_IFDIR)
    {
        strncpy(builtin_cwd, cwd, PATH_MAX);
    }
    else
    {
        fprintf(stderr, "directory does not exist\n");
        return;
    }
    chdir(builtin_cwd);
}

#endif // SKIN_BUILTIN_C
