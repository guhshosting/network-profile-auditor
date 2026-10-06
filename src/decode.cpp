#include "npa.hpp"
#include <iomanip>
#include <sstream>
namespace npa {
std::string hex(std::uint32_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << v;
    return s.str();
}
std::string category(std::optional<std::uint32_t> v) {
    if (!v)
        return "unavailable";
    switch (*v) {
    case 0:
        return "public";
    case 1:
        return "private";
    case 2:
        return "domain_authenticated";
    default:
        return "unknown(" + hex(*v) + ")";
    }
}
std::string domain(std::optional<std::uint32_t> v) {
    if (!v)
        return "unavailable";
    switch (*v) {
    case 0:
        return "non_domain_network";
    case 1:
        return "domain_network_not_authenticated";
    case 2:
        return "domain_authenticated";
    default:
        return "unknown(" + hex(*v) + ")";
    }
}
std::string oper(std::uint32_t v) {
    switch (v) {
    case 1:
        return "up";
    case 2:
        return "down";
    case 3:
        return "testing";
    case 4:
        return "unknown";
    case 5:
        return "dormant";
    case 6:
        return "not_present";
    case 7:
        return "lower_layer_down";
    default:
        return "unknown(" + hex(v) + ")";
    }
}
std::vector<std::string> connectivity(std::optional<std::uint32_t> v) {
    if (!v)
        return {};
    if (*v == 0)
        return {"disconnected"};
    struct Flag {
        std::uint32_t bit;
        const char *label;
    };
    constexpr Flag flags[] = {{1, "ipv4_no_traffic"},        {2, "ipv6_no_traffic"},  {0x10, "ipv4_subnet"},
                              {0x20, "ipv4_local_network"},  {0x40, "ipv4_internet"}, {0x100, "ipv6_subnet"},
                              {0x200, "ipv6_local_network"}, {0x400, "ipv6_internet"}};
    std::vector<std::string> out;
    std::uint32_t known = 0;
    for (const auto &f : flags) {
        known |= f.bit;
        if ((*v & f.bit) != 0)
            out.emplace_back(f.label);
    }
    if ((*v & ~known) != 0)
        out.push_back("unknown_bits(" + hex(*v & ~known) + ")");
    return out;
}
bool virtual_candidate(const Interface &i) {
    return (!i.hardware && i.type != 24) || i.type == 23 || i.type == 131;
}
} // namespace npa
