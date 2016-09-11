# MemDig: a memory cheat tool

MemDig allows the user to manipulate the memory of another process,
primary for the purposes of cheating. There have been many tools like
this before, but this one is a scriptable command line program.

There are a number of commands available from the program's command
prompt. The "help" command provides a list with documentation. MemDig
commands can also be supplied as command line arguments to the program
itself, by prefixing them with one or two dashes.

All commands can be shortened so long as they remain unambiguous,
similar to gdb. For example, "attach" can be written as "a" or "att".

The current set of commands is quite meager, though it can operate on
integers and floats of any size. The command set will grow as more
power is needed.

## Example Usage

Here's how you might change the amount of gold in a game called
Generic RPG. Suppose the process name is `grpg.exe` and you currently
have 273 gold, stored as a 32-bit integer.

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

## Supported Types

Suffixes can be used to set the type when searching memory. There are
three integer width specifiers: byte (o), short (h), and quad (q), and
each integer type is optionally unsigned (uo, uh, u, uq). For floating
point, include a decimal or exponent in the normal format. An f suffix
indicates single precision.

* -45o (signed 8-bit)
* 40000uh (unsigned 16-bit)
* 0xffffq (unsigned 64-bit)
* 10.0 (double)
* 1e1f (float)

## Supported Platforms

Currently Windows and Linux are supported. The platform API is fully
abstracted, so support for additional platforms could be easily added.

## Future Plans

* Remote, network interface
* More values types (strings, SIMD)
* Better handling of NaN and inf
* Readline support (especially on Linux)
* Automatic re-attach
* Watchlist editing (add, remove)
* Save/load address lists by name, to file
* Address list transformations and filters
* Progress indicator (find)
* Symbol and region oriented commands (locate known addresses after ASLR)
* (long shot) Export/create trainer EXE for a specific target
