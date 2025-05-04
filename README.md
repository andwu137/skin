# skin
It is a shell for humans?

# Features
- REPL
- command substitutions
- directory functions
- command pipes

# TODO
- language
    - return / error codes
    - return code booleans
    - loops
    - define functions
        - allow functions to work in name position
    - call stack
    - math ops
- read/eval:
    - command to string substitutions
- read:
    - custom prompt
    - get user input:
        - arrows
        - history
        - autocomplete
- eval:
    - glob paths
    - builtins: bg, fg
    - better error messages
- process signals
    - if process is fg, then send SIGINT
    - usr cancel
