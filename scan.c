/* Poor man's templates. */

static int
SCAN_NAME(struct watchlist *wl, char op, SCAN_TYPE value)
{
    struct region_iterator it[1];
    region_iterator_init(it, wl->process);
    for (; !region_iterator_done(it); region_iterator_next(it)) {
        SCAN_TYPE *buf;
        if ((buf = region_iterator_memory(it))) {
            size_t count = it->size / sizeof(buf[0]);
            for (size_t i = 0; i < count; i++) {
                switch (op) {
                    case '>':
                        if (buf[i] > value)
                            watchlist_push(wl, it->base + i * sizeof(buf[0]));
                        break;
                    case '<':
                        if (buf[i] < value)
                            watchlist_push(wl, it->base + i * sizeof(buf[0]));
                        break;
                    case '=':
                        if (buf[i] == value)
                            watchlist_push(wl, it->base + i * sizeof(buf[0]));
                        break;
                }
            }
        } else {
            LOG_INFO("memory read failed [0x%016" PRIxPTR "]: %s\n",
                     it->base, os_last_error());
        }
    }
    region_iterator_destroy(it);
    return 1;
}

struct NARROW_NAME {
    struct watchlist *watchlist;
    SCAN_TYPE value;
    char op;
};

static void
NARROW_NAME(uintptr_t addr, const void *memory, void *arg)
{
    struct NARROW_NAME *s = arg;
    if (memory) {
        const SCAN_TYPE *value = memory;
        switch (s->op) {
            case '>':
                if (*value > s->value)
                    watchlist_push(s->watchlist, addr);
                break;
            case '<':
                if (*value < s->value)
                    watchlist_push(s->watchlist, addr);
                break;
            case '=':
                if (*value == s->value)
                    watchlist_push(s->watchlist, addr);
                break;
        }
    } else {
        LOG_INFO("memory read failed [0x%016" PRIxPTR "]: %s\n",
                 addr, os_last_error());
    }
}
