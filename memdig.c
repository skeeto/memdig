#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define PROMPT "> "

/* Platform API */

#define REGION_ITERATOR_DONE    (1UL << 0)
#define REGION_ITERATOR_READ    (1UL << 1)
#define REGION_ITERATOR_WRITE   (1UL << 2)
#define REGION_ITERATOR_EXECUTE (1UL << 3)

#if 0 // (missing typedefs)
struct process_iterator;
int   process_iterator_init(struct process_iterator *);
int   process_iterator_next(struct process_iterator *);
int   process_iterator_done(struct process_iterator *);
void  process_iterator_destroy(struct process_iterator *);

struct region_iterator;
int   region_iterator_init(struct region_iterator *, os_handle);
int   region_iterator_next(struct region_iterator *);
int   region_iterator_done(struct region_iterator *);
void *region_iterator_memory(struct region_iterator *);
void  region_iterator_destroy(struct region_iterator *);

int os_write_memory(os_handle, uintptr_t, void *, size_t);
void  os_sleep(double);
os_handle os_process_open(os_pid);
void os_process_close(os_handle);
const char *os_last_error(void);
#endif

/* Platform implementation */

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>

typedef HANDLE os_handle;
typedef DWORD os_pid;

struct process_iterator {
    os_pid pid;
    char *name;

    // private
    HANDLE snapshot;
    char buf[MAX_PATH];
    int done;
    PROCESSENTRY32 entry;
};

static int
process_iterator_next(struct process_iterator *i)
{
    if (Process32Next(i->snapshot, &i->entry)) {
        strcpy(i->name, i->entry.szExeFile);
        i->pid = i->entry.th32ProcessID;
        return 1;
    } else {
        return !(i->done = 1);
    }
}

static int
process_iterator_init(struct process_iterator *i)
{
    i->entry = (PROCESSENTRY32){sizeof(i->entry)};
    i->done = 0;
    i->name = i->buf;
    i->snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry[1] = {{sizeof(entry)}};
    if (Process32First(i->snapshot, entry))
        return process_iterator_next(i);
    else
        return !(i->done = 1);
}

static int
process_iterator_done(struct process_iterator *i)
{
    return i->done;
}

static void
process_iterator_destroy(struct process_iterator *i)
{
    CloseHandle(i->snapshot);
}

struct region_iterator {
    uintptr_t base;
    size_t size;
    unsigned long flags;

    // private
    void *p;
    HANDLE process;
    void *buf;
    size_t bufsize;
};

static int
region_iterator_next(struct region_iterator *i)
{
    MEMORY_BASIC_INFORMATION info[1];
    for (;;) {
        if (VirtualQueryEx(i->process, i->p, info, sizeof(info))) {
            i->flags = 0;
            i->p = (char *)i->p + info->RegionSize;
            if (info->State == MEM_COMMIT) {
                i->size = info->RegionSize;
                i->base = (uintptr_t)info->AllocationBase;
                switch (info->AllocationProtect) {
                    case PAGE_EXECUTE:
                        i->flags |= REGION_ITERATOR_EXECUTE;
                        break;
                    case PAGE_EXECUTE_READ:
                        i->flags |= REGION_ITERATOR_READ;
                        i->flags |= REGION_ITERATOR_EXECUTE;
                        break;
                    case PAGE_EXECUTE_READWRITE:
                        i->flags |= REGION_ITERATOR_READ;
                        i->flags |= REGION_ITERATOR_WRITE;
                        i->flags |= REGION_ITERATOR_EXECUTE;
                        break;
                    case PAGE_EXECUTE_WRITECOPY:
                        i->flags |= REGION_ITERATOR_READ;
                        i->flags |= REGION_ITERATOR_WRITE;
                        i->flags |= REGION_ITERATOR_EXECUTE;
                        break;
                    case PAGE_READWRITE:
                        i->flags |= REGION_ITERATOR_READ;
                        i->flags |= REGION_ITERATOR_WRITE;
                        break;
                    case PAGE_READONLY:
                        i->flags |= REGION_ITERATOR_READ;
                        break;
                    case PAGE_WRITECOPY:
                        i->flags |= REGION_ITERATOR_READ;
                        i->flags |= REGION_ITERATOR_WRITE;
                        break;
                }
                break;
            }
        } else {
            i->flags = REGION_ITERATOR_DONE;
            break;
        }
    }
    return !(i->flags & REGION_ITERATOR_DONE);
}

static int
region_iterator_init(struct region_iterator *i, os_handle process)
{
    *i = (struct region_iterator){.process = process};
    return region_iterator_next(i);
}

static int
region_iterator_done(struct region_iterator *i)
{
    return !!(i->flags & REGION_ITERATOR_DONE);
}

static void *
region_iterator_memory(struct region_iterator *i)
{
    if (i->bufsize < i->size) {
        free(i->buf);
        i->bufsize = i->size;
        i->buf = malloc(i->bufsize);
    }
    size_t actual;
    void *base = (void *)i->base;
    if (!ReadProcessMemory(i->process, base, i->buf, i->size, &actual))
        return NULL;
    else if (actual < i->size)
        return NULL;
    return i->buf;
}

static void
region_iterator_destroy(struct region_iterator *i)
{
    free(i->buf);
    i->buf = NULL;
}

static int
os_write_memory(os_handle target, uintptr_t base, void *buf, size_t bufsize)
{
    size_t actual;
    return WriteProcessMemory(target, (void *)base, buf, bufsize, &actual)
        && actual == bufsize;
}

static void
os_sleep(double seconds)
{
    DWORD ms = (DWORD)(seconds * 1000);
    Sleep(ms);
}

static os_handle
os_process_open(os_pid id)
{
    DWORD access = PROCESS_VM_READ |
                   PROCESS_VM_WRITE |
                   PROCESS_VM_OPERATION |
                   PROCESS_QUERY_INFORMATION;
    HANDLE process = OpenProcess(access, 0, id);
    return process;
}

static void
os_process_close(os_handle h)
{
    CloseHandle(h);
}

static char error_buffer[4096];

static const char *
os_last_error(void)
{
    DWORD e = GetLastError();
    SetLastError(0);
    DWORD lang = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    FormatMessage(flags, 0, e, lang, error_buffer, sizeof(error_buffer), 0);
    for (char *p = error_buffer; *p; p++)
        if (*p == '\n')
            *p = 0;
    return error_buffer;
}

#endif // _WIN32

/* Logging */

static enum loglevel {
    LOGLEVEL_DEBUG   = -2,
    LOGLEVEL_INFO    = -1,
    LOGLEVEL_WARNING =  0,
    LOGLEVEL_ERROR   =  1,
} loglevel = 0;

#define FATAL(...)                                      \
    do {                                                \
        fprintf(stderr, "memdig: " __VA_ARGS__);        \
        exit(-1);                                       \
    } while (0)

#define LOG_ERROR(...)                                  \
    do {                                                \
        if (loglevel <= LOGLEVEL_ERROR)                 \
            fprintf(stderr, "error: " __VA_ARGS__);     \
        goto fail;                                      \
    } while (0)

#define LOG_WARNING(...)                                \
    do {                                                \
        if (loglevel <= LOGLEVEL_WARNING)               \
            fprintf(stderr, "warning: " __VA_ARGS__);   \
    } while (0)

#define LOG_INFO(...)                                   \
    do {                                                \
        if (loglevel <= LOGLEVEL_INFO)                  \
            fprintf(stderr, "info: " __VA_ARGS__);      \
    } while (0)

#define LOG_DEBUG(...)                                  \
    do {                                                \
        if (loglevel <= LOGLEVEL_DEBUG)                 \
            fprintf(stderr, "debug: " __VA_ARGS__);     \
    } while (0)

/* Watchlist */

struct watchlist {
    os_handle process;
    size_t count;
    size_t size;
    uintptr_t *addr;
};

static void
watchlist_init(struct watchlist *s, os_handle process)
{
    s->process = process;
    s->size = 4096;
    s->count = 0;
    s->addr = malloc(s->size * sizeof(s->addr[0]));
}

static void
watchlist_push(struct watchlist *s, uintptr_t v)
{
    if (s->count == s->size) {
        s->size *= 2;
        s->addr = realloc(s->addr, s->size * sizeof(s->addr[0]));
    }
    s->addr[s->count++] = v;
}

static void
watchlist_free(struct watchlist *s)
{
    free(s->addr);
    s->addr = NULL;
}

static void
watchlist_clear(struct watchlist *s)
{
    s->count = 0;
}

/* Memory scanning */

static void
scan32_full(struct watchlist *wl, uint32_t value)
{
    struct region_iterator it[1];
    region_iterator_init(it, wl->process);
    for (; !region_iterator_done(it); region_iterator_next(it)) {
        uint32_t *buf;
        if ((buf = region_iterator_memory(it))) {
            size_t count = it->size / sizeof(buf[0]);
            for (size_t i = 0; i < count; i++) {
                if (buf[i] == value)
                    watchlist_push(wl, it->base + i * sizeof(buf[0]));
            }
        } else {
            LOG_INFO("memory read failed [%p]: %s\n",
                     (void *)it->base, os_last_error());
        }
    }
    region_iterator_destroy(it);
}

typedef void (*region_visitor)(uintptr_t, const void *, void *);

static void
region_visit(struct watchlist *wl, region_visitor f, void *arg)
{
    struct region_iterator it[1];
    region_iterator_init(it, wl->process);
    size_t n = 0;
    for (; !region_iterator_done(it) && n < wl->count; region_iterator_next(it)) {
        char *buf = NULL;
        uintptr_t base = it->base;
        uintptr_t tail = base + it->size;
        while (n < wl->count && wl->addr[n] < base)
            n++;
        while (n < wl->count && wl->addr[n] >= base && wl->addr[n] < tail) {
            if (!buf)
                buf = region_iterator_memory(it);
            uintptr_t addr = wl->addr[n];
            if (buf) {
                size_t d = wl->addr[n] - base;
                f(addr, buf + d, arg);
            } else {
                f(addr, NULL, arg);
            }
            n++;
        }
    }
    region_iterator_destroy(it);
}

struct visitor_state {
    struct watchlist *wl;
    uint32_t value;
};

static void
narrow_visitor(uintptr_t addr, const void *memory, void *arg)
{
    struct visitor_state *s = arg;
    if (memory) {
        if (*(uint32_t *)memory == s->value)
            watchlist_push(s->wl, addr);
    } else {
        LOG_INFO("memory read failed [%p]: %s\n",
                 (void *)addr, os_last_error());
    }
}

static void
scan32_narrow(struct watchlist *wl, uint32_t value)
{
    struct watchlist out[1];
    watchlist_init(out, wl->process);
    struct visitor_state state = {
        .wl = out,
        .value = value
    };
    region_visit(wl, narrow_visitor, &state);
    watchlist_free(wl);
    *wl = *out;
}

static void
display_memory_regions(os_handle target)
{
    struct region_iterator it[1];
    region_iterator_init(it, target);
    for (; !region_iterator_done(it); region_iterator_next(it)) {
        char protect[4] = {
            it->flags & REGION_ITERATOR_READ    ? 'R' : ' ',
            it->flags & REGION_ITERATOR_WRITE   ? 'W' : ' ',
            it->flags & REGION_ITERATOR_EXECUTE ? 'X' : ' ',
        };
        uintptr_t tail = it->base + it->size;
        printf("%s %p %p %10zu bytes\n",
               protect, (void *)it->base, (void *)tail, it->size);
    }
    region_iterator_destroy(it);
}

/* Processes */

enum find_result {
    FIND_SUCCESS,
    FIND_FAILURE,
    FIND_AMBIGUOUS,
};

static os_pid
process_find(const char *pattern, os_pid *pid)
{
    struct process_iterator it[1];
    process_iterator_init(it);
    *pid = 0;
    os_pid target_pid = 0;
    if (pattern[0] == ':')
        target_pid = strtol(pattern + 1, NULL, 10);
    for (; !process_iterator_done(it); process_iterator_next(it)) {
        if (target_pid == it->pid || strstr(it->name, pattern)) {
            if (*pid)
                return FIND_AMBIGUOUS;
            *pid = it->pid;
        }
    }
    process_iterator_destroy(it);
    if (!*pid)
        return FIND_FAILURE;
    return FIND_SUCCESS;
}

/* Command processing */

enum command {
    COMMAND_AMBIGUOUS = -2,
    COMMAND_UNKNOWN = -1,
    COMMAND_ATTACH = 0,
    COMMAND_MEMORY,
    COMMAND_FIND,
    COMMAND_NARROW,
    COMMAND_LIST,
    COMMAND_SET,
    COMMAND_WAIT,
    COMMAND_HELP,
    COMMAND_QUIT,
};

static struct {
    const char *name;
    const char *help;
    const char *args;
} command_info[] = {
    [COMMAND_ATTACH] = {
        "attach", "select a new target process",
        "[:pid|pattern]"
    },
    [COMMAND_MEMORY] = {
        "memory", "list committed memory regions",
        0
    },
    [COMMAND_FIND]   = {
        "find", "find and remember integral memory values",
        "<current value>"
    },
    [COMMAND_NARROW] = {
        "narrow", "filter the current list of addresses",
        "<current value>"
    },
    [COMMAND_LIST]   = {
        "list", "show the current address list",
        "[proc|addr]"
    },
    [COMMAND_SET]    = {
        "set", "set memory at each listed address",
        "<new value>"
    },
    [COMMAND_WAIT]   = {
        "wait", "wait a fractional number of seconds",
        "<seconds>"
    },
    [COMMAND_HELP]   = {
        "help", "print this help information",
        0},
    [COMMAND_QUIT]   = {
        "quit", "exit the program",
        0},
};

static enum command
command_parse(const char *c)
{
    unsigned n = sizeof(command_info) / sizeof(command_info[0]);
    size_t len = strlen(c);
    enum command command = COMMAND_UNKNOWN;
    for (unsigned i = 0; i < n; i++)
        if (strncmp(command_info[i].name, c, len) == 0) {
            if (command != COMMAND_UNKNOWN)
                return COMMAND_AMBIGUOUS;
            else
                command = i;
        }
    return command;
}

/* High level Memdig API */

struct memdig {
    os_pid id;
    os_handle target;
    struct watchlist watchlist;
};

static void
memdig_init(struct memdig *m)
{
    *m = (struct memdig){0, 0};
}

static void
list_visitor(uintptr_t addr, const void *mem, void *arg)
{
    (void)arg;
    if (mem)
        printf("%p %" PRIu32 "\n", (void *)addr, *(uint32_t *)mem);
    else
        printf("%p ???\n", (void *)addr);
}

enum memdig_result {
    MEMDIG_RESULT_ERROR = -1,
    MEMDIG_RESULT_OK = 0,
    MEMDIG_RESULT_QUIT = 1,
};

static enum memdig_result
memdig_exec(struct memdig *m, int argc, char **argv)
{
    if (argc == 0)
        return MEMDIG_RESULT_OK;
    char *verb = argv[0];
    enum command command = command_parse(verb);
    switch (command) {
        case COMMAND_AMBIGUOUS: {
            LOG_ERROR("ambiguous command '%s'\n", verb);
        } break;
        case COMMAND_UNKNOWN: {
            LOG_ERROR("unknown command '%s'\n", verb);
        } break;
        case COMMAND_ATTACH: {
            if (argc == 1) {
                if (m->target)
                    printf("attached to %ld\n", (long)m->id);
                else
                    printf("not attached to a process\n");
            } else if (argc != 2)
                LOG_ERROR("wrong number of arguments");
            if (m->target) {
                watchlist_free(&m->watchlist);
                os_process_close(m->target);
                m->target = 0;
            }
            char *pattern = argv[1];
            switch (process_find(pattern, &m->id)) {
                case FIND_FAILURE:
                    LOG_ERROR("no process found for '%s'\n", pattern);
                    break;
                case FIND_AMBIGUOUS:
                    LOG_ERROR("ambiguous target '%s'\n", pattern);
                    break;
                case FIND_SUCCESS:
                    if (!(m->target = os_process_open(m->id))) {
                        if (!m->target)
                            LOG_ERROR("open process %ld failed: %s\n",
                                      (long)m->id, os_last_error());
                        m->id = 0;
                    } else {
                        watchlist_init(&m->watchlist, m->target);
                        printf("attached to %ld\n", (long)m->id);
                    }
                    break;
            }
        } break;
        case COMMAND_MEMORY: {
            if (!m->target)
                LOG_ERROR("no process attached\n");
            display_memory_regions(m->target);
        } break;
        case COMMAND_FIND: {
            if (!m->target)
                LOG_ERROR("no process attached\n");
            if (argc != 2)
                LOG_ERROR("wrong number of arguments");
            long value = strtol(argv[1], NULL, 10);
            watchlist_clear(&m->watchlist);
            scan32_full(&m->watchlist, value);
            printf("%zu values found\n", m->watchlist.count);
        } break;
        case COMMAND_NARROW: {
            if (!m->target)
                LOG_ERROR("no process attached\n");
            if (argc != 2)
                LOG_ERROR("wrong number of arguments");
            long value = strtol(argv[1], NULL, 10);
            scan32_narrow(&m->watchlist, value);
            printf("%zu values remaining\n", m->watchlist.count);
        } break;
        case COMMAND_LIST: {
            char arg = 'a';
            if (argc > 1)
                arg = argv[1][0];
            switch (arg) {
                case 'a': {
                    if (!m->target)
                        LOG_ERROR("no process attached\n");
                    region_visit(&m->watchlist, list_visitor, 0);
                } break;
                case 'p': {
                    struct process_iterator it[1];
                    process_iterator_init(it);
                    for (; !process_iterator_done(it); process_iterator_next(it))
                        printf("%8ld %s\n", (long)it->pid, it->name);
                    process_iterator_destroy(it);
                } break;
                default: {
                    LOG_ERROR("unknown list type '%s'\n", argv[1]);
                } break;
            }
        } break;
        case COMMAND_SET: {
            if (!m->target)
                LOG_ERROR("no process attached\n");
            if (argc != 2)
                LOG_ERROR("wrong number of arguments");
            uint32_t value = strtol(argv[1], NULL, 10);
            size_t set_count = 0;
            for (size_t i = 0; i < m->watchlist.count; i++) {
                uintptr_t addr = m->watchlist.addr[i];
                if (!os_write_memory(m->target, addr, &value, sizeof(value)))
                    LOG_WARNING("write memory failed: %s\n",
                                os_last_error());
                else
                    set_count++;
            }
            printf("%zu values set\n", set_count);
        } break;
        case COMMAND_WAIT: {
            if (argc != 2)
                LOG_ERROR("wrong number of arguments");
            os_sleep(atof(argv[1]));
        } break;
        case COMMAND_HELP: {
            unsigned n = sizeof(command_info) / sizeof(command_info[0]);
            for (unsigned i = 0; i < n; i++) {
                const char *name = command_info[i].name;
                const char *help = command_info[i].help;
                const char *args = command_info[i].args;
                int argsize = (int)(26 - strlen(name));
                printf("%s %-*s %s\n", name, argsize, args ? args : "", help);
            }
            putchar('\n');
            puts("Commands can also be supplied as command line arguments, "
                 "where each\ncommand verb is prefixed with one or two "
                 "dashes.");

        } break;
        case COMMAND_QUIT: {
            return MEMDIG_RESULT_QUIT;
        } break;
    }
    return MEMDIG_RESULT_OK;
fail:
    return MEMDIG_RESULT_ERROR;
}

static void
memdig_free(struct memdig *m)
{
    if (m->target) {
        watchlist_free(&m->watchlist);
        os_process_close(m->target);
    }
}

int
main(int argc, char **argv)
{
    int result = 0;
    struct memdig memdig[1];
    memdig_init(memdig);

    char *xargv[16];
    int xargc = 0;
    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        xargc = 1;
        xargv[0] = argv[i++];
        while (xargv[0][0] == '-' && xargv[0][0] != 0)
            xargv[0]++;
        while (i < argc && argv[i][0] != '-' && xargc < 15)
            xargv[xargc++] = argv[i++];
        xargv[xargc] = NULL;
        enum memdig_result r = memdig_exec(memdig, xargc, xargv);
        if (r == MEMDIG_RESULT_ERROR)
            result = -1;
        if (r != MEMDIG_RESULT_OK)
            goto quit;
        if (strcmp(xargv[0], "help") == 0)
            goto quit;
        if (strcmp(xargv[0], "version") == 0)
            goto quit;
    }

    char line[4096];
    fputs(PROMPT, stdout);
    const char *delim = " \n\t";
    while (fgets(line, sizeof(line), stdin)) {
        xargc = 0;
        xargv[0] = strtok(line, delim);
        if (xargv[0]) {
            do
                xargc++;
            while (xargc < 15 && (xargv[xargc] = strtok(NULL, delim)));
            xargv[xargc] = NULL;
        }
        if (memdig_exec(memdig, xargc, xargv) == MEMDIG_RESULT_QUIT)
            goto quit;
        fputs(PROMPT, stdout);
    }

quit:
    memdig_free(memdig);
    return result;
}
