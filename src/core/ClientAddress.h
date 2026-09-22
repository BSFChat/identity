#pragma once

#include <httplib.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// A copy of the chat server's src/http/ClientAddress.{h,cpp} (server
// origin/main ed7bd1d), namespaced for this service. Security audit H2: the
// identity service keyed every limiter on the TCP peer, which behind the
// shipped nginx is one docker gateway address for every user. It now resolves
// clients exactly the way the chat server does, so an operator configures
// `[auth] trusted_proxies` once, with one meaning, for both services. Keep the
// two copies in step; there is no shared library between the repos to hold it.

namespace bsfchat::id {

// An IPv4 or IPv6 network in CIDR form. IPv4 is held as an IPv4-mapped IPv6
// address so one comparison path serves both families, and so a dual-stack
// listener reporting "::ffff:10.0.0.1" matches a "10.0.0.0/8" entry.
struct IpNetwork {
    std::array<uint8_t, 16> addr{};
    int prefix_bits = 128; // always in IPv6 terms (IPv4 /n is stored as 96 + n)

    // Accepts "10.0.0.0/8", "192.168.1.1", "fd00::/8", "::1". Returns nullopt
    // for anything else, including a prefix length out of range for the family.
    static std::optional<IpNetwork> parse(const std::string& cidr);

    [[nodiscard]] bool contains(const std::array<uint8_t, 16>& ip) const;

    // True when this network was written in IPv4 form (and so is held as an
    // IPv4-mapped /96+n).
    [[nodiscard]] bool is_v4() const;

    // The prefix length as the operator wrote it: 15 for "162.158.0.0/15",
    // 29 for "2a06:98c0::/29". `prefix_bits` is the internal, always-IPv6
    // form and is 96 larger for IPv4, which makes it useless for anything an
    // operator reads.
    [[nodiscard]] int cidr_prefix() const;
};

// True when EVERY address in `net` lies inside loopback or one of the private
// ranges — i.e. when it is a plausible entry for auth.trusted_proxies.
//
// Trusting a network is trusting its X-Forwarded-For, so a trusted network
// that reaches into public address space is an off switch for every
// per-address limit on the server: anything inside it picks its own identity
// once per request. Containment, not overlap: "0.0.0.0/0" and "10.0.0.0/4"
// both include private space and neither is safe to trust.
bool is_private_or_loopback_network(const IpNetwork& net);

// True when `net` is too wide for any proxy fleet to occupy — a default route,
// or a slice of the internet so large that "these are my edge nodes" cannot be
// a true statement about it.
//
// This is the floor under the acknowledgement in auth.trusted_public_proxies.
// An operator fronting the origin with a CDN has a real reason to trust public
// address space and should be able to say so once and have the server believe
// them; what they must NOT be able to do is say it about "0.0.0.0/0" and have
// the per-address limits quietly stop existing. So a network this wide keeps
// warning no matter which key it was written under.
//
// The thresholds are set from what real edge fleets actually publish, with
// room to spare: Cloudflare's widest block is a /13 (IPv4) and a /29 (IPv6),
// AWS CloudFront's is a /14, and the CGNAT range an overlay network like
// Tailscale sits in is 100.64.0.0/10. Everything at or below those passes;
// "0.0.0.0/0", "::/0", a public /8 and "2000::/3" (the whole global unicast
// space) do not.
bool is_too_wide_to_be_a_proxy_fleet(const IpNetwork& net);

// An address in a form that is safe to put in a log line.
//
// ── Why this exists ───────────────────────────────────────────────────────
// Operator logs are shipped off the host and read by people who are not the
// operator. The identity service's security log lines (failed logins,
// lockouts, the untrusted-proxy warning) are worth keeping, but they do not
// need the last octet: a /24 (or /64) answers every question an operator asks
// of them without being a record of which subscriber tried to log in when.
// Same policy as the chat server.
//
// ── The shape ─────────────────────────────────────────────────────────────
//   "203.0.113.42"     -> "203.0.113.0/24"
//   "2001:db8::1:2:3"  -> "2001:db8::/64"
//   anything unparseable, or empty -> "unparseable"
//
// Never returns the input unchanged, and never returns an empty string: a log
// call site must not be able to leak a full address by passing something this
// function did not recognise.
std::string redact_ip_for_log(const std::string& address);

// Works out which address a request should be attributed to for rate limiting.
//
// This service is documented as running behind a reverse proxy, where the
// socket peer is the PROXY for every request. Keying a limiter on that would
// put the entire internet in one bucket: the first person to trip it locks
// everybody out, which is a worse outage than the attack being limited. So
// the peer address is only believed when the peer is not a known proxy, and
// X-Forwarded-For is only believed when the peer IS one — otherwise any
// client could mint itself a fresh identity per request by sending the header.
class ClientAddressResolver {
public:
    // Throws std::invalid_argument naming the offending entry if one does not
    // parse. A typo here must not be silently dropped: the entry it was meant
    // to add is the difference between per-client limits and one shared bucket.
    explicit ClientAddressResolver(const std::vector<std::string>& trusted_proxies);

    // The client's address in canonical form, with IPv6 collapsed to its /64
    // (a single subscriber routinely controls a whole /64, so per-address
    // limits would be no limit at all) — or nullopt when the client cannot be
    // told apart from other clients:
    //
    //   * the peer is a trusted proxy but sent no usable X-Forwarded-For, or
    //     every hop in it is itself a trusted proxy;
    //   * the peer address is missing or unparseable.
    //
    // Callers must treat nullopt as "skip per-address limits", never as a
    // shared bucket.
    [[nodiscard]] std::optional<std::string> resolve(const httplib::Request& req) const;

    // True when the request looks like it came through a reverse proxy that is
    // NOT in the trusted list: a private or loopback peer that nevertheless
    // supplied X-Forwarded-For. Every client of such a deployment shares the
    // proxy's bucket until the operator lists it; callers use this to say so
    // in the log.
    [[nodiscard]] bool looks_like_untrusted_proxy(const httplib::Request& req) const;

private:
    [[nodiscard]] bool is_trusted(const std::array<uint8_t, 16>& ip) const;

    std::vector<IpNetwork> trusted_;
};

} // namespace bsfchat::id
