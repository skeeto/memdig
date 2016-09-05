#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define PROMPT(f)                               \
    do {                                        \
        fputs("> ", f);                         \
        fflush(f);                              \
    } while(0)

/* Platform API */

#define REGION_ITERATOR_DONE    (1UL << 0)
#define REGION_ITERATOR_READ    (1UL << 1)
#define REGION_ITERATOR_WRITE   (1UL << 2)
#define REGION_ITERATOR_EXECUTE (1UL << 3)

#define PROCESS_ITERATOR_DONE   (1UL << 0)

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
    unsigned long flags;

    // private
    HANDLE snapshot;
    char buf[MAX_PATH];
    PROCESSENTRY32 entry;
};

static int
process_iterator_next(struct process_iterator *i)
{
    if (Process32Next(i->snapshot, &i->entry)) {
        strcpy(i->name, i->entry.szExeFile);
        i->pid = i->entry.th32ProcessID;
        return !(i->flags = 0);
    } else {
        return !(i->flags = PROCESS_ITERATOR_DONE);
    }
}

static int
process_iterator_init(struct process_iterator *i)
{
    i->entry = (PROCESSENTRY32){sizeof(i->entry)};
    i->flags = PROCESS_ITERATOR_DONE;
    i->name = i->buf;
    i->snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry[1] = {{sizeof(entry)}};
    if (Process32First(i->snapshot, entry))
        return process_iterator_next(i);
    else
        return 0;
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

static void *
region_iterator_memory(struct region_iterator *i)
{
    if (i->bufsize < i->size) {
        free(i->buf);
        i->bufsize = i->size;
        i->buf = malloc(i->bufsize);
    }
    SIZE_T actual;
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
    SIZE_T actual;
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

#elif __linux__
#include <math.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#include <dirent.h>
#include <sys/uio.h>

typedef pid_t os_handle;
typedef pid_t os_pid;

struct process_iterator {
    os_pid pid;
    char *name;
    unsigned long flags;

    // private
    size_t i;
    size_t count;
    pid_t *pids;
    char buf[256];
};

static int
process_iterator_next(struct process_iterator *i)
{
    for (;;) {
        if (i->i == i->count)
            return !(i->flags = PROCESS_ITERATOR_DONE);
        i->pid = i->pids[++i->i];
        sprintf(i->buf, "/proc/%ld/status", (long)i->pid);
        FILE *f = fopen(i->buf, "r");
        if (f) {
            if (fgets(i->buf, sizeof(i->buf), f)) {
                char *p = i->buf;
                for (; *p && *p != '\t'; p++);
                i->name = p + (*p ? 1 : 0);
                for (; *p; p++)
                    if (*p == '\n')
                        *p = 0;
                fclose(f);
                return !(i->flags = 0);
            } else {
                fclose(f);
            }
        }
    }
}

static int
pid_cmp(const void *a, const void *b)
{
    return (int)*(pid_t *)a - (int)*(pid_t *)b;
}

static int
process_iterator_init(struct process_iterator *i)
{
    size_t size = 4096;
    *i = (struct process_iterator){
        .i = (size_t)-1,
        .pids = malloc(sizeof(i->pids[0]) * size),
        .flags = PROCESS_ITERATOR_DONE,
    };
    DIR *dir = opendir("/proc");
    if (!dir)
        return 0;
    struct dirent *e;
    while ((e = readdir(dir))) {
        int valid = 1;
        for (char *p = e->d_name; *p; p++)
            if (*p < '0' || *p > '9')
                valid = 0;
        if (valid) {
            if (i->count == size) {
                size *= 2;
                i->pids = realloc(i->pids, sizeof(i->pids[0]) * size);
            }
            i->pids[i->count++] = atoi(e->d_name);
        }
    }
    qsort(i->pids, i->count, sizeof(i->pids[0]), pid_cmp);
    closedir(dir);
    return process_iterator_next(i);
}

static void
process_iterator_destroy(struct process_iterator *i)
{
    free(i->pids);
    i->pids = NULL;
}

struct region_iterator {
    uintptr_t base;
    size_t size;
    unsigned long flags;

    //private
    pid_t pid;
    FILE *maps;
    char *buf;
    size_t bufsize;
};

static int
region_iterator_next(struct region_iterator *i)
{
    char perms[8];
    uintptr_t beg, end;
    int r = fscanf(i->maps, "%" SCNxPTR "-%" SCNxPTR " %7s", &beg, &end, perms);
    if (r != 3) {
        i->flags = REGION_ITERATOR_DONE;
        return 0;
    }
    int c;
    do
        c = fgetc(i->maps);
    while (c != '\n' && c != EOF);
    i->base = beg;
    i->size = end - beg;
    i->flags = 0;
    if (perms[0] == 'r')
        i->flags |= REGION_ITERATOR_READ;
    if (perms[1] == 'w')
        i->flags |= REGION_ITERATOR_WRITE;
    if (perms[2] == 'x')
        i->flags |= REGION_ITERATOR_EXECUTE;
    return 1;
}

static int
region_iterator_init(struct region_iterator *i, os_handle pid)
{
    i->flags = REGION_ITERATOR_DONE;
    char file[256];
    sprintf(file, "/proc/%ld/maps", (long)pid);
    FILE *maps = fopen(file, "r");
    if (!maps)
        return 0;
    *i = (struct region_iterator){
        .pid = pid,
        .maps = maps,
    };
    return region_iterator_next(i);
}

static void *
region_iterator_memory(struct region_iterator *i)
{
    if (i->bufsize < i->size) {
        free(i->buf);
        i->bufsize = i->size;
        i->buf = malloc(i->bufsize);
    }
    struct iovec local = {
        .iov_base = i->buf,
        .iov_len  = i->size,
    };
    struct iovec remote = {
        .iov_base = (void *)i->base,
        .iov_len  = i->size,
    };
    ssize_t in = process_vm_readv(i->pid, &local, 1, &remote, 1, 0);
    return (in >= 0 && (size_t)in == i->size) ? i->buf : NULL;
}

static void
region_iterator_destroy(struct region_iterator *i)
{
    fclose(i->maps);
    free(i->buf);
    i->buf = NULL;
}

static int
os_write_memory(os_handle pid, uintptr_t addr, void *buf, size_t bufsize)
{
    struct iovec local = {
        .iov_base = buf,
        .iov_len  = bufsize,
    };
    struct iovec remote = {
        .iov_base = (void *)addr,
        .iov_len  = bufsize,
    };
    ssize_t out = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return out >= 0 && (size_t)out == bufsize;
}

static void
os_sleep(double s)
{
    struct timespec ts = {
        .tv_sec = s,
        .tv_nsec = (s - trunc(s)) * 1e9,
    };
    nanosleep(&ts, 0);
}

static os_handle
os_process_open(os_pid pid)
{
    return pid; // TODO: verify capability
}

static void
os_process_close(os_handle h)
{
    (void)h; // nothing to do
}

const char *
os_last_error(void)
{
    return strerror(errno);
}

#endif // __linux__

static int
process_iterator_done(struct process_iterator *i)
{
    return !!(i->flags & PROCESS_ITERATOR_DONE);
}

static int
region_iterator_done(struct region_iterator *i)
{
    return !!(i->flags & REGION_ITERATOR_DONE);
}

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

#define xstr(s) str(s)
#define str(s) #s

#define SCAN_NAME scan_u8
#define NARROW_NAME narrow_u8
#define SCAN_TYPE uint8_t
#include "scan.c"
#undef SCAN_NAME
#undef NARROW_NAME
#undef SCAN_TYPE

#define SCAN_NAME scan_s8
#define NARROW_NAME narrow_s8
#define SCAN_TYPE int8_t
#include "scan.c"
#undef SCAN_NAME
#undef NARROW_NAME
#undef SCAN_TYPE

#define SCAN_NAME scan_u16
#define NARROW_NAME narrow_u16
#define SCAN_TYPE uint16_t
#include "scan.c"
#undef SCAN_NAME
#undef NARROW_NAME
#undef SCAN_TYPE

#define SCAN_NAME scan_s16
#define NARROW_NAME narrow_s16
#define SCAN_TYPE int16_t
#include "scan.c"
#undef SCAN_NAME
#undef NARROW_NAME
#undef SCAN_TYPE

#define SCAN_NAME scan_u32
#define NARROW_NAME narrow_u32
#define SCAN_TYPE uint32_t
#include "scan.c"
#undef SCAN_NAME
#undef NARROW_NAME
#undef SCAN_TYPE

#define SCAN_NAME scan_s32
#define NARROW_NAME narrow_s32
#define SCAN_TYPE int32_t
#include "scan.c"
#undef SCAN_NAME
#undef NARROW_NAME
#undef SCAN_TYPE

#define SCAN_NAME scan_u64
#define NARROW_NAME narrow_u64
#define SCAN_TYPE uint64_t
#include "scan.c"
#undef SCAN_NAME
#undef NARROW_NAME
#undef SCAN_TYPE

#define SCAN_NAME scan_s64
#define NARROW_NAME narrow_s64
#define SCAN_TYPE int64_t
#include "scan.c"
#undef SCAN_NAME
#undef NARROW_NAME
#undef SCAN_TYPE

#define SCAN_NAME scan_f32
#define NARROW_NAME narrow_f32
#define SCAN_TYPE float
#include "scan.c"
#undef SCAN_NAME
#undef NARROW_NAME
#undef SCAN_TYPE

#define SCAN_NAME scan_f64
#define NARROW_NAME narrow_f64
#define SCAN_TYPE double
#include "scan.c"
#undef SCAN_NAME
#undef NARROW_NAME
#undef SCAN_TYPE

struct scan_value {
    enum scan_value_type {
        SCAN_VALUE_S8,
        SCAN_VALUE_U8,
        SCAN_VALUE_S16,
        SCAN_VALUE_U16,
        SCAN_VALUE_S32,
        SCAN_VALUE_U32,
        SCAN_VALUE_S64,
        SCAN_VALUE_U64,
        SCAN_VALUE_F32,
        SCAN_VALUE_F64,
    } type;
    union {
        int64_t s;
        uint64_t u;
        double f;
    } value;
};

static int
scan_value_parse(struct scan_value *v, const char *arg)
{
    v->type = SCAN_VALUE_S64;
    int is_hex = 0;
    char *end;
    if (strncmp(arg, "0x", 2) == 0) {
        is_hex = 1;
        v->type = SCAN_VALUE_U64;
        errno = 0;
        v->value.u = strtoull(arg + 2, &end, 16);
    } else {
        errno = 0;
        v->value.s = strtoll(arg, &end, 10);
    }
    if (!is_hex && *end == 'u') {
        if (arg[0] == '-')
            return 0;
        // try again as unsigned
        v->type = SCAN_VALUE_U64;
        errno = 0;
        v->value.u = strtoull(arg, &end, 10);
        end++;
    } else if (!is_hex && *end == '.') {
        errno = 0;
        v->value.f = strtod(arg, &end);
        if (errno)
            return 0;
        if (strcmp(end, "f") == 0)
            v->type = SCAN_VALUE_F32;
        else if (strcmp(end, "") == 0)
            v->type = SCAN_VALUE_F64;
        else
            return 0;
        return 1;
    } else if (errno) {
        return 0;
    }
    if (end[0] && end[1])
        return 0; // too much suffix
    switch (*end) {
        case 'b':
            v->type -= 6;
            return 1;
        case 'h':
            v->type -= 4;
            return 1;
        case 0:
            v->type -= 2;
            return 1;
        case 'q':
            return 1;
    }
    return 0;
}

static void
scan_value_pointer(struct scan_value *v, void *buf, unsigned *size)
{
    switch (v->type) {
        case SCAN_VALUE_S8:
            *size = 1;
            *(int8_t *)buf = (int8_t)v->value.s;
            break;
        case SCAN_VALUE_U8:
            *size = 1;
            *(uint8_t *)buf = (uint8_t)v->value.u;
            break;
        case SCAN_VALUE_S16:
            *size = 2;
            *(int16_t *)buf = (int16_t)v->value.s;
            break;
        case SCAN_VALUE_U16:
            *size = 2;
            *(uint16_t *)buf = (uint16_t)v->value.u;
            break;
        case SCAN_VALUE_S32:
            *size = 4;
            *(int32_t *)buf = (int32_t)v->value.s;
            break;
        case SCAN_VALUE_U32:
            *size = 4;
            *(uint32_t *)buf = (uint32_t)v->value.u;
            break;
        case SCAN_VALUE_S64:
            *size = 8;
            *(int64_t *)buf = v->value.s;
            break;
        case SCAN_VALUE_U64:
            *size = 8;
            *(uint64_t *)buf = v->value.u;
            break;
        case SCAN_VALUE_F32:
            *size = 4;
            *(float *)buf = (float)v->value.f;
            break;
        case SCAN_VALUE_F64:
            *size = 8;
            *(double *)buf = v->value.f;
            break;
    }
}

static int
scan(struct watchlist *wl, char op, struct scan_value *v)
{
    watchlist_clear(wl);
    switch (v->type) {
        case SCAN_VALUE_S8:
            return scan_s8(wl, op, (int8_t)v->value.s);
        case SCAN_VALUE_U8:
            return scan_u8(wl, op, (uint8_t)v->value.u);
        case SCAN_VALUE_S16:
            return scan_s16(wl, op, (int16_t)v->value.s);
        case SCAN_VALUE_U16:
            return scan_u16(wl, op, (uint16_t)v->value.u);
        case SCAN_VALUE_S32:
            return scan_s32(wl, op, (int32_t)v->value.s);
        case SCAN_VALUE_U32:
            return scan_u32(wl, op, (uint32_t)v->value.u);
        case SCAN_VALUE_S64:
            return scan_s64(wl, op, v->value.s);
        case SCAN_VALUE_U64:
            return scan_u64(wl, op, v->value.u);
        case SCAN_VALUE_F32:
            return scan_f32(wl, op, (float)v->value.f);
        case SCAN_VALUE_F64:
            return scan_f64(wl, op, v->value.f);
    }
    return 0;
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

static int
narrow(struct watchlist *wl, char op, struct scan_value *v)
{
    struct watchlist out[1];
    watchlist_init(out, wl->process);
    switch (v->type) {
        case SCAN_VALUE_S8: {
            struct narrow_s8 state = {
                .watchlist = out,
                .op = op,
                .value = (int8_t)v->value.s,
            };
            region_visit(wl, narrow_s8, &state);
        } break;
        case SCAN_VALUE_U8: {
            struct narrow_u8 state = {
                .watchlist = out,
                .op = op,
                .value = (uint8_t)v->value.u,
            };
            region_visit(wl, narrow_u8, &state);
        } break;
        case SCAN_VALUE_S16: {
            struct narrow_s16 state = {
                .watchlist = out,
                .op = op,
                .value = (int16_t)v->value.s,
            };
            region_visit(wl, narrow_s16, &state);
        } break;
        case SCAN_VALUE_U16: {
            struct narrow_u16 state = {
                .watchlist = out,
                .op = op,
                .value = (uint16_t)v->value.u,
            };
            region_visit(wl, narrow_u16, &state);
        } break;
        case SCAN_VALUE_S32: {
            struct narrow_s32 state = {
                .watchlist = out,
                .op = op,
                .value = (int32_t)v->value.s,
            };
            region_visit(wl, narrow_s32, &state);
        } break;
        case SCAN_VALUE_U32: {
            struct narrow_u32 state = {
                .watchlist = out,
                .op = op,
                .value = (uint32_t)v->value.u,
            };
            region_visit(wl, narrow_u32, &state);
        } break;
        case SCAN_VALUE_S64: {
            struct narrow_s64 state = {
                .watchlist = out,
                .op = op,
                .value = v->value.s,
            };
            region_visit(wl, narrow_s64, &state);
        } break;
        case SCAN_VALUE_U64: {
            struct narrow_u64 state = {
                .watchlist = out,
                .op = op,
                .value = v->value.u,
            };
            region_visit(wl, narrow_u64, &state);
        } break;
        case SCAN_VALUE_F32: {
            struct narrow_f32 state = {
                .watchlist = out,
                .op = op,
                .value = (float)v->value.f,
            };
            region_visit(wl, narrow_f32, &state);
        } break;
        case SCAN_VALUE_F64: {
            struct narrow_f64 state = {
                .watchlist = out,
                .op = op,
                .value = v->value.f,
            };
            region_visit(wl, narrow_f64, &state);
        } break;
    }
    watchlist_free(wl);
    *wl = *out;
    return 1;
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
        printf("%s 0x%016" PRIxPTR " 0x%016" PRIxPTR " %10zu bytes\n",
               protect, it->base, tail, it->size);
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
    COMMAND_PUSH,
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
        "[<|>|=] <value>"
    },
    [COMMAND_NARROW] = {
        "narrow", "filter the current list of addresses",
        "[<|>|=] <value>"
    },
    [COMMAND_PUSH] = {
        "push", "manually add address to list",
        "<address>"
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
        printf("0x%016" PRIxPTR " %" PRIu32 "\n", addr, *(uint32_t *)mem);
    else
        printf("0x%016" PRIxPTR " ???\n", addr);
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
                return MEMDIG_RESULT_OK;
            } else if (argc != 2)
                LOG_ERROR("wrong number of arguments\n");
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
            if (argc < 2 || argc > 3)
                LOG_ERROR("wrong number of arguments\n");
            char op = '=';
            const char *value = argv[1];
            if (argc == 3) {
                op = argv[1][0];
                if (strlen(argv[1]) != 1 || !strchr("<=>", op))
                    LOG_ERROR("invalid operator '%s'\n", argv[1]);
                value = argv[2];
            }
            struct scan_value scan_value;
            if (!scan_value_parse(&scan_value, value))
                LOG_ERROR("invalid value '%s'\n", value);
            if (!scan(&m->watchlist, op, &scan_value))
                LOG_ERROR("scan failure'\n");
            else
                printf("%zu values found\n", m->watchlist.count);
        } break;
        case COMMAND_NARROW: {
            if (!m->target)
                LOG_ERROR("no process attached\n");
            if (argc < 2 || argc > 3)
                LOG_ERROR("wrong number of arguments\n");
            char op = '=';
            const char *value = argv[1];
            if (argc == 3) {
                op = argv[1][0];
                if (strlen(argv[1]) != 1 || !strchr("<=>", op))
                    LOG_ERROR("invalid operator '%s'\n", argv[1]);
                value = argv[2];
            }
            struct scan_value scan_value;
            if (!scan_value_parse(&scan_value, value))
                LOG_ERROR("invalid value '%s'\n", value);
            if (!narrow(&m->watchlist, op, &scan_value))
                LOG_ERROR("scan failure'\n");
            else
                printf("%zu values found\n", m->watchlist.count);
        } break;
        case COMMAND_PUSH: {
            if (!m->target)
                LOG_ERROR("no process attached\n");
            if (argc != 2)
                LOG_ERROR("wrong number of arguments");
            char *addrs = argv[1];
            if (strncmp(addrs, "0x", 2) != 0)
                LOG_ERROR("unknown address format '%s'\n", addrs);
            uintptr_t addr = (uintptr_t)strtoull(addrs + 2, NULL, 16);
            watchlist_push(&m->watchlist, addr);
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
            const char *value = argv[1];
            struct scan_value scan_value;
            if (!scan_value_parse(&scan_value, value))
                LOG_ERROR("invalid value '%s'\n", value);
            size_t set_count = 0;
            for (size_t i = 0; i < m->watchlist.count; i++) {
                uintptr_t addr = m->watchlist.addr[i];
                unsigned size = 0;
                char buf[8];
                scan_value_pointer(&scan_value, buf, &size);
                if (!os_write_memory(m->target, addr, buf, size))
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
                 "dashes.\n");
            puts("By default, memory is scanned for 32-bit signed integers. "
                 "The numeric\narguments to find, narrow, and set may have "
                 "C-like suffixes specifying\ntheir width and signedness "
                 "(b, h, q, ub, uh, uq). Floating point\nvalues are also "
                 "an option, with an 'f' suffix for single precision.");
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
    PROMPT(stdout);
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
        PROMPT(stdout);
    }

quit:
    memdig_free(memdig);
    return result;
}
