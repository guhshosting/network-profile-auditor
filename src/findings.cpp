#include "npa.hpp"
#include <algorithm>
namespace npa {
void find(Result &r) {
    r.findings.clear();
    const auto add = [&](const std::string &code, const std::string &subject, const std::string &message) {
        r.findings.push_back({code, subject, message});
    };
    std::size_t active = 0;
    for (const auto &n : r.networks) {
        if (n.connected == true)
            ++active;
        const auto id = n.id.value_or("unavailable");
        if (n.category && *n.category <= 2)
            add(category(n.category) + "_profile", id,
                "Windows reports category " + category(n.category) +
                    "; category influences Windows policy/firewall behavior.");
        if (n.connectivity == 0u)
            add("no_connectivity", id, "Windows reports no connectivity for this network.");
    }
    if (active > 1)
        add("multiple_active_profiles", "snapshot",
            "Windows reports " + std::to_string(active) + " active network profiles.");
    for (const auto &c : r.correlations) {
        if (r.interface_api_available && c.adapter_id && !c.interface_index)
            add("profile_interface_unavailable", c.network_id.value_or("unavailable"),
                "Profile connection references adapter " + *c.adapter_id +
                    " absent from the local interface snapshot.");
    }
    for (std::size_t j = 0; j < r.interfaces.size(); ++j) {
        const auto &i = r.interfaces[j];
        if (virtual_candidate(i))
            add("virtual_vpn_candidate", i.id,
                "Windows reports a non-hardware, PPP or tunnel interface; virtual/VPN candidate.");
        if (i.oper_status == 1 && r.profile_api_available && r.profile_enumeration_complete) {
            const bool mapped = std::any_of(r.correlations.begin(), r.correlations.end(),
                                            [&](const Correlation &c) { return c.interface_index == j; });
            if (!mapped)
                add("active_interface_without_profile", i.id,
                    "Operationally up interface has no correlation to a profile in the selected NLM "
                    "snapshot.");
        }
    }
}
} // namespace npa
