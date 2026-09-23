/* SPDX-FileCopyrightText: 2026 The Nikasha Authors */
/* SPDX-License-Identifier: Apache-2.0 */
#include <stdlib.h>
#include <string.h>

#define BUF_MAX 256
#define CLAMP(v, hi) ((v) > (hi) ? clamp_hi(v, hi) : (v))
#define LOG_CALL(fn, arg) \
    do { trace_enter(#fn); fn(arg); } while (0)

struct packet {
    unsigned char *data;
    size_t len;
};

typedef struct session session_t;

union word {
    unsigned int u;
    float f;
};

enum mode { MODE_OFF, MODE_ON };

typedef int (*handler_fn)(struct packet *pkt);

struct ops {
    handler_fn on_packet;
    void (*on_close)(void);
};

static int clamp_hi(int v, int hi);

static inline int clamp_hi(int v, int hi)
{
    return v > hi ? hi : v;
}

static int handle_packet(struct packet *pkt)
{
    char *copy = malloc(pkt->len);
    memcpy(copy, pkt->data, pkt->len);
    free(copy);
    return CLAMP((int)pkt->len, BUF_MAX);
}

static void handle_close(void)
{
}

static const struct ops default_ops = {
    .on_packet = handle_packet,
    .on_close = handle_close,
};

char **
split_words(const char *text, size_t *count)
{
    char **out = calloc(8, sizeof(*out));
    *count = 0;
    (void)text;
    return out;
}

int dispatch(const struct ops *ops, struct packet *pkt, handler_fn fallback)
{
    int (*fp)(struct packet *) = fallback;
    if (ops->on_packet(pkt) != 0)
        return (*fp)(pkt);
    register_handler(handle_packet);
    ops->on_close();
    return 0;
}
