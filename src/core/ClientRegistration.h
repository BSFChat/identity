#pragma once

#include "core/Config.h"
#include "store/IdentityStore.h"

#include <string>

namespace bsfchat::id {

// The first-party client's registration, and the startup reconciliation that
// keeps an existing database in step with it.
//
// Its own translation unit rather than part of IdentityServer so a test can
// exercise it against an in-memory store: constructing an IdentityServer
// means key directories, an HTTP server and a sweeper thread, none of which
// this decision depends on, and none of which tests/identity_tests links.
// IdentityServer's constructor calls ensure_first_party_client() and nothing
// else touches the registration.
//
// See ClientRegistration.cpp for what is registered: a loopback client for
// desktop and a claimed-https client for mobile. The private-use
// "bsfchat://" redirect is no longer registered by default, because any app
// can claim it and sign in AS the first-party client.

// The JSON array of redirect URIs "bsfchat-desktop" is registered with.
const char* first_party_redirect_uris();

// The two first-party public clients: desktop (loopback) and mobile (claimed
// https redirect). See ClientRegistration.cpp for why they are separate.
const char* desktop_client_id();
const char* mobile_client_id();
bool is_first_party_client(const std::string& client_id);

// Create the client if it is absent; otherwise upgrade a registration that
// still holds one of the exact values this project shipped previously. An
// operator's customised list is left alone.
void ensure_first_party_client(IdentityStore& store, const Config& config);

} // namespace bsfchat::id
