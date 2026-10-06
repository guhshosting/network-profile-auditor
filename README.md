# network-profile-auditor 1.0.0

> Release context: see [qualified platforms, runtime requirements and package scope](RELEASE-QUALIFICATION.md).


A native, read-only Windows command-line auditor of local network profiles and interfaces. It reads what Windows reports without testing the network. MIT licensed, C++17, Unicode, no third-party runtime dependencies. Release builds statically link the Microsoft C++ runtime.

```text
network-profile-auditor
network-profile-auditor --all
network-profile-auditor --json
network-profile-auditor --all --json
network-profile-auditor --help
network-profile-auditor --version
```

The default emphasizes NLM networks with `IsConnected` true, retaining networks whose connected state is unavailable. `--all` also displays disconnected/remembered networks exposed by Network List Manager. All local interfaces are displayed in either mode, including disconnected and logical interfaces. Findings apply to the selected snapshot. This is not an inventory of saved Wi-Fi configurations.

Windows assigns public, private, or domain-authenticated categories to networks. The category affects Windows policy and firewall behavior; public does not by itself mean insecure, and private does not prove security. The tool neither determines open firewall ports nor changes categories. Domain type is reported separately, distinguishing a domain network from domain authentication. Unknown enum values and flag bits are preserved.

Connectivity is Windows-reported metadata. IPv4 and IPv6 flags may indicate no detected traffic, subnet, local network, or Internet connectivity; zero means disconnected. A Windows Internet flag is not proof that an application can reach the Internet now. No ping, DNS query, HTTP request, public-IP lookup, captive-portal check, communication socket, or Wi-Fi scan is performed.

NLM networks supply identity, name, category, connected state, connectivity, and domain type. Each NLM connection supplies a connection GUID and TCP/IP adapter GUID. IP Helper `GetIfTable2` supplies interface GUIDs, LUIDs, indexes, Unicode aliases/descriptions, operational status, hardware/filter indicators, and interface/tunnel types. Correlation compares the API-generated canonical GUIDs directly. Multiple connections can reference one interface; a profile can have multiple connections. Missing mappings remain visible. Interface up does not imply usable connectivity.

Hyper-V, VPN and other virtual adapters appear when Windows exposes them. Non-hardware (except loopback), PPP, and tunnel interfaces are marked virtual/VPN **candidates**, based on API fields. No name matching, vendor recognition, SSID analysis, or physical-NIC assumption is used. VPN identity cannot reliably be established from these fields. Interfaces without NLM correlation can be normal, especially loopback and logical interfaces.

The application has an `asInvoker` manifest, requests no elevation, and is intended to operate unelevated. A failed property produces null/unavailable metadata plus a warning with HRESULT. Failure of IP Helper leaves profile information usable. A failed NLM activation/enumeration preventing a useful profile audit exits 3; an incomplete enumeration with usable profiles yields a partial snapshot and warning. Zero successfully enumerated networks is a valid result. Snapshots are not atomic, so correlations may change during collection.

Exit codes: 0 completed (including factual findings and partial metadata); 2 usage; 3 profile/network API unavailable preventing a useful audit; 4 unexpected failure or output failure. Help/version exit without acquisition. Unknown, repeated, and incompatible options are rejected.

Human output includes profile summary, Windows connectivity flags, interfaces, correlations, findings, warnings, and limitations. Console text uses `WriteConsoleW`; redirected output is UTF-8 without a BOM. Names are quoted with escaped control characters. Unpaired UTF-16 surrogates exposed by Windows are replaced with U+FFFD. See [JSON.md](JSON.md) for machine output.

## Build and install

Supported targets: Windows 10, Windows 11, and corresponding Windows Server generations, x64. Primary live validation: Windows Server 2025 x64. The APIs predate these targets; other OS editions and architectures have not been live validated. Use Visual Studio Build Tools with C++ desktop tools, CMake 3.24+, and Windows SDK. No network-dependent packages are needed.

In an x64 Native Tools command prompt:

```bat
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix install
```

Configure separate Debug, `-DNPA_ANALYZE=ON` Release, and `-DNPA_ASAN=ON` RelWithDebInfo builds for MSVC analysis and AddressSanitizer. `scripts/validate.ps1` runs the validation matrix on this host; its tool paths can be supplied as parameters. The validation scripts require PowerShell 7, ripgrep, clang-tidy and Cppcheck. Validation scripts may use PowerShell and developer tools; the installed application never invokes them. [VALIDATION.md](VALIDATION.md) records actual outcomes and limitations.

## Read-only and no-network design

Application acquisition uses only COM initialization, in-process NLM activation, NLM enumerators/getters and local IP Helper table enumeration. Resources use RAII. It never calls networking setters, Registry APIs, service-control APIs, network configuration commands, WLAN APIs, resolver APIs, or socket communication APIs. It does not launch external executables. Building and tests are distinct from application behavior.

NLM is a Windows service-backed metadata API. Existing Windows services may independently perform connectivity detection or other network activity. The guarantee is no intentional network communication or active probing by this application, not system-wide silence. Source and executable import review support this design; packet-level proof is only claimed if actually obtained in validation.

No category changes, network connection changes, adapter changes, firewall/DNS/route/Registry modifications, service restarts, passwords, remote systems, speed tests, or GUI are supported.

## API references

- [Network List Manager](https://learn.microsoft.com/en-us/windows/win32/api/netlistmgr/)
- [Network adapter GUID](https://learn.microsoft.com/en-us/windows/win32/api/netlistmgr/nf-netlistmgr-inetworkconnection-getadapterid)
- [Network category](https://learn.microsoft.com/en-us/windows/win32/api/netlistmgr/ne-netlistmgr-nlm_network_category)
- [Connectivity flags](https://learn.microsoft.com/en-us/windows/win32/api/netlistmgr/ne-netlistmgr-nlm_connectivity)
- [Domain type](https://learn.microsoft.com/en-us/windows/win32/api/netlistmgr/ne-netlistmgr-nlm_domain_type)
- [GetIfTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2)
- [MIB_IF_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2)
