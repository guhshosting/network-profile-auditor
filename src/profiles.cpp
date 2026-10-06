#include "windows_support.hpp"
#include <netlistmgr.h>
namespace npa {
namespace {
template <class T, class Getter>
void property(Result &r, const std::string &label, std::optional<std::uint32_t> &out, Getter getter) {
    T v{};
    const auto hr = getter(&v);
    if (SUCCEEDED(hr))
        out = static_cast<std::uint32_t>(v);
    else
        warn(r, label, hr);
}
template <class Getter>
void identifier(Result &r, const std::string &label, std::optional<std::string> &out, Getter getter) {
    GUID v{};
    const auto hr = getter(&v);
    if (SUCCEEDED(hr))
        out = guid(v);
    else
        warn(r, label, hr);
}
template <class Getter>
void connected(Result &r, const std::string &label, std::optional<bool> &out, Getter getter) {
    VARIANT_BOOL v{};
    const auto hr = getter(&v);
    if (SUCCEEDED(hr))
        out = (v != VARIANT_FALSE);
    else
        warn(r, label, hr);
}
} // namespace
void acquire_profiles(Result &r) {
    Apartment apartment;
    if (FAILED(apartment.status())) {
        warn(r, "COM initialization", apartment.status());
        return;
    }
    ComPtr<INetworkListManager> manager;
    auto hr = CoCreateInstance(CLSID_NetworkListManager, nullptr, CLSCTX_INPROC_SERVER,
                               IID_INetworkListManager, reinterpret_cast<void **>(manager.put()));
    if (FAILED(hr)) {
        warn(r, "Network List Manager", hr);
        return;
    }
    ComPtr<IEnumNetworks> networks;
    hr = manager->GetNetworks(NLM_ENUM_NETWORK_ALL, networks.put());
    if (FAILED(hr)) {
        warn(r, "Network enumeration", hr);
        return;
    }
    r.profile_api_available = true;
    for (;;) {
        ComPtr<INetwork> network;
        ULONG fetched = 0;
        hr = networks->Next(1, network.put(), &fetched);
        if (FAILED(hr)) {
            warn(r, "Network enumeration (partial snapshot)", hr);
            break;
        }
        if (fetched == 0) {
            r.profile_enumeration_complete = true;
            break;
        }
        if (!network.get()) {
            r.warnings.push_back("Network enumerator returned an empty object.");
            break;
        }
        Network n;
        identifier(r, "Network ID", n.id, [&](GUID *p) { return network->GetNetworkId(p); });
        const auto context = "Network " + n.id.value_or("(ID unavailable)");
        Bstr name;
        hr = network->GetName(name.put());
        if (SUCCEEDED(hr))
            n.name = name.text();
        else
            warn(r, context + " name", hr);
        property<NLM_NETWORK_CATEGORY>(r, context + " category", n.category,
                                       [&](NLM_NETWORK_CATEGORY *p) { return network->GetCategory(p); });
        property<NLM_CONNECTIVITY>(r, context + " connectivity", n.connectivity,
                                   [&](NLM_CONNECTIVITY *p) { return network->GetConnectivity(p); });
        property<NLM_DOMAIN_TYPE>(r, context + " domain type", n.domain_type,
                                  [&](NLM_DOMAIN_TYPE *p) { return network->GetDomainType(p); });
        connected(r, context + " connected state", n.connected,
                  [&](VARIANT_BOOL *p) { return network->get_IsConnected(p); });
        r.networks.push_back(n);
        ComPtr<IEnumNetworkConnections> connections;
        hr = network->GetNetworkConnections(connections.put());
        if (FAILED(hr)) {
            warn(r, context + " connections", hr);
            continue;
        }
        for (;;) {
            ComPtr<INetworkConnection> connection;
            fetched = 0;
            hr = connections->Next(1, connection.put(), &fetched);
            if (FAILED(hr)) {
                warn(r, context + " connection enumeration", hr);
                break;
            }
            if (fetched == 0)
                break;
            if (!connection.get()) {
                r.warnings.push_back(context + " returned an empty connection object.");
                break;
            }
            Correlation c;
            c.network_id = n.id;
            identifier(r, context + " connection ID", c.connection_id,
                       [&](GUID *p) { return connection->GetConnectionId(p); });
            identifier(r, context + " adapter ID", c.adapter_id,
                       [&](GUID *p) { return connection->GetAdapterId(p); });
            property<NLM_CONNECTIVITY>(r, context + " connection connectivity", c.connectivity,
                                       [&](NLM_CONNECTIVITY *p) { return connection->GetConnectivity(p); });
            property<NLM_DOMAIN_TYPE>(r, context + " connection domain type", c.domain_type,
                                      [&](NLM_DOMAIN_TYPE *p) { return connection->GetDomainType(p); });
            connected(r, context + " connection state", c.connected,
                      [&](VARIANT_BOOL *p) { return connection->get_IsConnected(p); });
            r.correlations.push_back(std::move(c));
        }
    }
}
} // namespace npa
