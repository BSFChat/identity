#pragma once

#include "store/IdentityStore.h"

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
// See ClientRegistration.cpp for what is registered and why a private-use
// URI scheme is safe here (short version: this client is public, so PKCE is
// mandatory, so a code stolen by another app that claimed the scheme cannot
// be redeemed).

// The JSON array of redirect URIs "bsfchat-desktop" is registered with.
const char* first_party_redirect_uris();

// Create the client if it is absent; otherwise upgrade a registration that
// still holds one of the exact values this project shipped previously. An
// operator's customised list is left alone.
void ensure_first_party_client(IdentityStore& store);

} // namespace bsfchat::id
