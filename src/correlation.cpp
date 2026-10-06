#include "npa.hpp"
#include <algorithm>
namespace npa {
void correlate(Result &r) {
    for (auto &c : r.correlations) {
        c.interface_index.reset();
        if (!c.adapter_id.has_value())
            continue;
        const auto adapter_id = c.adapter_id.value();
        for (std::size_t j = 0; j < r.interfaces.size(); ++j) {
            if (adapter_id == r.interfaces[j].id) {
                c.interface_index = j;
                break;
            }
        }
    }
}
void select_current(Result &r) {
    if (r.all)
        return;
    // Unknown connected state is retained rather than silently hidden.
    std::vector<std::string> removed;
    for (const auto &n : r.networks)
        if (n.connected == false && n.id.has_value())
            removed.push_back(n.id.value_or(std::string{}));
    r.networks.erase(std::remove_if(r.networks.begin(), r.networks.end(),
                                    [](const Network &n) { return n.connected == false; }),
                     r.networks.end());
    r.correlations.erase(std::remove_if(r.correlations.begin(), r.correlations.end(),
                                        [&](const Correlation &c) {
                                            return c.network_id && std::find(removed.begin(), removed.end(),
                                                                             *c.network_id) != removed.end();
                                        }),
                         r.correlations.end());
}
Result audit(bool all) {
    Result r;
    r.all = all;
    acquire_profiles(r);
    acquire_interfaces(r);
    correlate(r);
    select_current(r);
    find(r);
    return r;
}
} // namespace npa
