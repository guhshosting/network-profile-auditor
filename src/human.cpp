#include "npa.hpp"
#include <algorithm>
#include <sstream>
namespace npa {
namespace {
std::string state(std::optional<bool> v) { return v ? (*v ? "active" : "disconnected") : "unavailable"; }
std::string flags(std::optional<std::uint32_t> v) {
    if (!v)
        return "unavailable";
    std::string out = hex(*v) + " [";
    bool first = true;
    for (const auto &f : connectivity(v)) {
        if (!first)
            out += ", ";
        first = false;
        out += f;
    }
    return out + ']';
}
} // namespace
std::string human(const Result &r) {
    std::ostringstream s;
    std::size_t active = 0, unknown = 0;
    for (const auto &n : r.networks) {
        if (n.connected == true)
            ++active;
        if (!n.connected)
            ++unknown;
    }
    const auto up = std::count_if(r.interfaces.begin(), r.interfaces.end(),
                                  [](const Interface &i) { return i.oper_status == 1; });
    s << "network-profile-auditor " << version << "\nLocal Windows network profile snapshot ("
      << (r.all ? "all NLM networks" : "current networks") << ")\n"
      << "Current profile summary: " << active << " Windows-reported active, " << unknown
      << " with unavailable active state; " << up << " operationally up interfaces.\n";
    if (!r.profile_api_available)
        s << "Profile/network API unavailable; useful profile audit could not complete.\n";
    else if (!r.profile_enumeration_complete)
        s << "Profile enumeration incomplete.\n";
    if (r.networks.empty() && r.profile_api_available)
        s << "No networks in the selected NLM snapshot.\n";
    s << "\nNetworks and profiles:\n";
    for (const auto &n : r.networks) {
        s << "  " << (n.name ? quote(*n.name) : "(name unavailable)") << " | "
          << n.id.value_or("ID unavailable") << "\n"
          << "    State: " << state(n.connected) << "; category: " << category(n.category) << " ("
          << (n.category ? hex(*n.category) : "unavailable") << "); domain: " << domain(n.domain_type) << "\n"
          << "    Windows-reported connectivity: " << flags(n.connectivity) << "\n";
        std::size_t matches = 0;
        for (const auto &c : r.correlations) {
            if (!n.id || c.network_id != n.id)
                continue;
            ++matches;
            s << "    Connection: " << c.connection_id.value_or("unavailable")
              << "; adapter: " << c.adapter_id.value_or("unavailable") << "\n";
            if (c.interface_index && *c.interface_index < r.interfaces.size()) {
                const auto &i = r.interfaces[*c.interface_index];
                s << "      Interface: " << quote(i.name) << "; index " << i.index << "; "
                  << oper(i.oper_status) << "\n";
            } else
                s << "      Interface mapping unavailable.\n";
            s << "      State: " << state(c.connected)
              << "; Windows-reported connectivity: " << flags(c.connectivity)
              << "; domain: " << domain(c.domain_type) << "\n";
        }
        if (matches == 0)
            s << "    No associated interface correlation available.\n";
    }
    s << "\nLocal interfaces (including disconnected/logical):\n";
    for (const auto &i : r.interfaces) {
        s << "  " << quote(i.name) << " | " << i.id << " | " << oper(i.oper_status) << "\n"
          << "    " << quote(i.description) << "; index " << i.index << "; LUID " << i.luid << "; type "
          << i.type << "; tunnel type " << i.tunnel_type << "; hardware " << (i.hardware ? "yes" : "no")
          << (virtual_candidate(i) ? "; virtual/VPN candidate" : "") << "\n";
    }
    s << "\nFindings (factual):\n";
    if (r.findings.empty())
        s << "  None in the selected snapshot.\n";
    for (const auto &f : r.findings)
        s << "  [" << f.code << "] " << f.subject << ": " << f.message << "\n";
    s << "\nWarnings:\n";
    if (r.warnings.empty())
        s << "  None.\n";
    for (const auto &w : r.warnings)
        s << "  " << w << "\n";
    s << "\nLimitations:\n";
    for (const auto &l : r.limitations)
        s << "  " << l << "\n";
    return s.str();
}
} // namespace npa
