CC     = x86_64-w64-mingw32-gcc
CFLAGS = -std=c99 -Wall -Wextra -O3 \
    -Wno-missing-field-initializers -D__USE_MINGW_ANSI_STDIO=1

memdig.exe : memdig.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean :
	$(RM) *.exe
