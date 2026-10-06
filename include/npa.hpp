#ifndef NPA_MODEL_HPP
#define NPA_MODEL_HPP
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace npa {
inline constexpr const char *version = "1.0.0";
struct Options {
    bool all = false;
    bool json = false;
    bool help = false;
    bool version = false;
};
Options parse(const std::vector<std::wstring> &args);
struct Network {
    std::optional<std::string> id, name;
    std::optional<std::uint32_t> category, connectivity, domain_type;
    std::optional<bool> connected;
};
struct Interface {
    std::string id, name, description;
    std::uint64_t luid = 0;
    std::uint32_t index = 0, type = 0, oper_status = 0, tunnel_type = 0;
    bool hardware = false, filter = false;
};
struct Correlation {
    std::optional<std::string> network_id, connection_id, adapter_id;
    std::optional<std::uint32_t> connectivity, domain_type;
    std::optional<bool> connected;
    std::optional<std::size_t> interface_index;
};
struct Finding {
    std::string code, subject, message;
};
struct Result {
    bool profile_api_available = false;
    bool profile_enumeration_complete = false;
    bool interface_api_available = false;
    bool all = false;
    std::vector<Network> networks;
    std::vector<Interface> interfaces;
    std::vector<Correlation> correlations;
    std::vector<Finding> findings;
    std::vector<std::string> warnings;
    std::vector<std::string> limitations{
        "Windows-reported connectivity is metadata, not a test that Internet access works.",
        ("Category influences Windows policy/firewall behavior; it does not establish network security or "
         "open ports."),
        "Acquisition is a non-atomic local snapshot; state can change during enumeration.",
        ("NLM networks represent profiles here; --all includes remembered networks exposed by NLM, not every "
         "stored Wi-Fi profile."),
        ("Interface up means operationally up, not proven connectivity. Logical interfaces need not have an "
         "NLM profile."),
        ("Non-hardware, PPP and tunnel indicators identify logical/virtual/VPN candidates; no vendor or VPN "
         "identity is inferred."),
        ("Only local metadata is read. No active probing, DNS queries, communication sockets or Wi-Fi "
         "scanning. Windows services may communicate independently.")};
};
std::string category(std::optional<std::uint32_t> v);
std::string domain(std::optional<std::uint32_t> v);
std::string oper(std::uint32_t v);
std::vector<std::string> connectivity(std::optional<std::uint32_t> v);
std::string hex(std::uint32_t v);
bool virtual_candidate(const Interface &i);
void acquire_profiles(Result &r);
void acquire_interfaces(Result &r);
void correlate(Result &r);
void find(Result &r);
void select_current(Result &r);
Result audit(bool all);
std::string utf8(const std::wstring &v);
std::wstring wide(const std::string &v);
std::string quote(const std::string &v);
std::string human(const Result &r);
std::string json(const Result &r);
bool write_output(const std::string &v, bool error = false);
} // namespace npa
#endif
