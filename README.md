# Memdig: a memory cheat tool

Memdig allows the user to manipulate the memory of another process,
primary for the purposes of cheating. There have been many tools like
this before, but this one is a scriptable command line program.

There are a number of commands available from the program's command
prompt. The "help" command provides a list with documentation. Memdig
commands can also be supplied as command line arguments to the program
itself, by prefixing them with one or two dashes.

All commands can be shortened so long as they remain unambiguous,
similar to gdb. For example, "attach" can be written as "a" or "att".

## Example Usage

Here's how you might change the amount of gold in a game called
Generic RPG. Suppose the process name is `grpg.exe` and you currently
have 273 gold.

    memdig.exe --attach grpg.exe
    > find 273
    317 values found

    (... perform an in-game action to change it to 312 gold ...)

    > narrow 312
    1 value found
    > set 1000000
    1 value set

If all goes well, you would now have 1 million gold.

The above could be scripted entirely as command arguments.

    memdig.exe -a grpg.exe -f 273 -w 10 -n 312 -s 1000000 -q

The `-w 10` (i.e. `--wait 10`) will put a 10 second delay before the
"narrow" command, giving you a chance to make changes to the game
state. The `-q` (i.e. `--quit`) will exit the program before it beings
the interactive prompt.

## Support Platforms

Since it's the largest platform for gaming, only Windows is currently
supported. However, the API to the platform is fully abstracted, so
support for additional platforms could easily be added.
