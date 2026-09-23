// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0
#include <cstring>
#include <vector>

#define CHECK(x) do { if (!(x)) fail_hard(__LINE__); } while (0)

namespace net {
namespace wire {

struct Header {
    int size;
};

class Reader {
public:
    explicit Reader(const char *buf) : buf_(buf) {}
    int next() { return decode(buf_++); }
    int peek() const;
    ~Reader();

private:
    const char *buf_;
};

template <typename T>
T clamp(T v, T hi)
{
    return v > hi ? hi : v;
}

}  // namespace wire

int Reader_helper(int x);

}  // namespace net

int net::wire::Reader::peek() const
{
    CHECK(buf_ != nullptr);
    return decode(buf_);
}

net::wire::Reader::~Reader()
{
    std::memset(nullptr, 0, 0);
}

static void on_event(int code)
{
    (void)code;
}

int run(net::wire::Reader &r, std::vector<int> &out)
{
    void (*cb)(int) = on_event;
    out.push_back(r.next());
    int v = net::wire::clamp<int>(r.peek(), 10);
    cb(v);
    return v;
}
