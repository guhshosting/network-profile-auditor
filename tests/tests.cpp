#include "npa.hpp"
#include "windows_support.hpp"
#include <algorithm>
#include <iostream>
#include <stdexcept>
namespace {
void check(bool v, const char *message) {
    if (!v)
        throw std::runtime_error(message);
}
bool has(const npa::Result &r, const std::string &code) {
    return std::any_of(r.findings.begin(), r.findings.end(),
                       [&](const npa::Finding &f) { return f.code == code; });
}
npa::Result fixture() {
    npa::Result r;
    r.all = true;
    r.profile_api_available = true;
    r.profile_enumeration_complete = true;
    r.interface_api_available = true;
    r.networks = {{"public-id", npa::utf8(L"公共\U0001F310\"\n"), 0, 0x42, 0, true},
                  {"private-id", "Private", 1, 0x10, 0, true},
                  {"domain-id", "Domain", 2, 0x400, 2, true},
                  {"unknown-id", "Future", 99, 0x80000000u, 99, std::nullopt},
                  {"disconnected-id", "Old", 0, 0, 0, false}};
    r.interfaces = {{"nic-id", npa::utf8(L"以太网\U0001F680"), "Physical", 18446744073709551615ull, 7, 6, 1,
                     0, true, false},
                    {"vpn-id", "Tunnel", "Logical", 2, 9, 131, 1, 1, false, false},
                    {"down-id", "Disconnected", "Virtual", 3, 10, 6, 2, 0, false, false},
                    {"loop-id", "Loopback", "Loopback", 4, 1, 24, 1, 0, false, false}};
    r.correlations = {
        {"public-id", "c1", "nic-id", 0x42, 0, true, std::nullopt},
        {"private-id", "c2", "nic-id", 0x10, 0, true, std::nullopt},
        {"domain-id", "c3", "gone-id", 0x400, 2, true, std::nullopt},
        {"disconnected-id", "c4", "down-id", 0, 0, false, std::nullopt},
        {"unknown-id", "c5", std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt},
        {"public-id", "c6", "vpn-id", 0x10, 0, true, std::nullopt}};
    npa::correlate(r);
    npa::find(r);
    return r;
}
void synthetic() {
    auto r = fixture();
    check(has(r, "public_profile") && has(r, "private_profile") && has(r, "domain_authenticated_profile"),
          "categories");
    check(has(r, "multiple_active_profiles") && has(r, "no_connectivity"), "active/disconnected findings");
    check(has(r, "profile_interface_unavailable") && has(r, "active_interface_without_profile"),
          "incomplete mappings");
    check(has(r, "virtual_vpn_candidate"), "virtual interface");
    check(r.correlations[0].interface_index == std::size_t{0} &&
              r.correlations[1].interface_index == std::size_t{0},
          "many to one");
    check(!r.correlations[2].interface_index && !r.correlations[4].interface_index, "unknown mapping");
    check(r.correlations[5].interface_index == std::size_t{1}, "one network to multiple interfaces");
    check(npa::category(99) == "unknown(0x63)" && npa::category(std::nullopt) == "unavailable",
          "unknown category");
    check(npa::domain(1) == "domain_network_not_authenticated", "domain authentication distinction");
    check(npa::connectivity(0) == std::vector<std::string>{"disconnected"}, "disconnected decoding");
    check(npa::connectivity(0x42) == std::vector<std::string>({"ipv6_no_traffic", "ipv4_internet"}),
          "mixed connectivity");
    check(npa::connectivity(0x80000000u) == std::vector<std::string>{"unknown_bits(0x80000000)"},
          "unknown flags");
    check(npa::connectivity(std::nullopt).empty(), "unavailable connectivity");
    const auto unicode = std::wstring(L"公共以太网\U0001F680");
    check(npa::wide(npa::utf8(unicode)) == unicode, "Unicode round trip");
    check(npa::quote(std::string("a\0\n\"\\", 5)) == "\"a\\u0000\\n\\\"\\\\\"", "JSON escaping");
    const auto output = npa::json(r);
    check(output.find("\"category_raw\":99") != std::string::npos &&
              output.find("\"windows_connectivity_raw\":2147483648") != std::string::npos,
          "JSON future numeric values");
    check(output.find("\"luid\":\"18446744073709551615\"") != std::string::npos, "LUID exactness");
    check(output.find(npa::utf8(L"公共")) != std::string::npos && output.find("\\n") != std::string::npos,
          "Unicode JSON");
    check(npa::human(r).find("\\n") != std::string::npos, "human control escaping");
    r.all = false;
    npa::select_current(r);
    npa::find(r);
    check(r.networks.size() == 4 && r.correlations.size() == 5,
          "current selection preserves unknown, excludes disconnected");
    r.interface_api_available = false;
    r.profile_enumeration_complete = false;
    npa::find(r);
    check(!has(r, "profile_interface_unavailable") && !has(r, "active_interface_without_profile"),
          "avoid absence finding when API incomplete");
    check(npa::parse({L"--all", L"--json"}).all, "combined CLI");
    for (const auto &args : std::vector<std::vector<std::wstring>>{
             {L"--bad"}, {L"--all", L"--all"}, {L"--help", L"--json"}, {L"--version", L"--all"}}) {
        bool rejected = false;
        try {
            (void)npa::parse(args);
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        check(rejected, "invalid CLI rejected");
    }
    npa::Result empty;
    npa::correlate(empty);
    npa::find(empty);
    check(npa::json(empty).find("\"networks\":[]") != std::string::npos, "empty JSON");
}
void live() {
    const auto r = npa::audit(true);
    check(r.profile_api_available && r.profile_enumeration_complete && r.interface_api_available,
          "live acquisition complete");
    std::size_t mapped = 0;
    for (const auto &c : r.correlations) {
        if (c.interface_index)
            check(c.adapter_id && *c.adapter_id == r.interfaces[*c.interface_index].id,
                  "live GUID correlation");
        if (c.interface_index)
            ++mapped;
    }
    check(!r.interfaces.empty(), "live interface table nonempty");
    if (std::any_of(r.networks.begin(), r.networks.end(),
                    [](const npa::Network &n) { return n.connected == true; }))
        check(mapped > 0, "live active network correlation exists");
    std::cout << "Live: " << r.networks.size() << " networks, " << r.interfaces.size() << " interfaces, "
              << r.correlations.size() << " connections, " << r.warnings.size() << " warnings\n";
}
} // namespace
int wmain(int argc, wchar_t **argv) {
    try {
        if (argc == 2 && std::wstring(argv[1]) == L"--live")
            live();
        else if (argc == 2 && std::wstring(argv[1]) == L"--fixture-json") {
            npa::write_output(npa::json(fixture()));
        } else
            synthetic();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
