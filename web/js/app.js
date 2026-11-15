// BSFChat ID - Shared JavaScript

async function apiRequest(method, url, body) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin'
    };
    if (body && method !== 'GET') {
        opts.body = JSON.stringify(body);
    }
    const res = await fetch(url, opts);
    const data = await res.json();
    if (!res.ok) {
        throw new Error(data.error || `Request failed (${res.status})`);
    }
    return data;
}

// ---- Authorization request round trip ----
//
// /authorize sends a signed-out browser to /login.html with the request in
// the query string (redirect_uri renamed to `redirect`). The login and
// register pages pass that query string to each other unchanged, and both
// finish through continueAfterSignIn(), so signing up from the app resumes
// the app's sign-in exactly as signing in does.

// Rebuild the /authorize request this page was sent from, if any.
//
// Every parameter is forwarded as it arrived (only `redirect` is renamed back
// to `redirect_uri`), so a parameter /authorize learns later — nonce,
// resource — survives the trip through these pages without this file having
// to know about it. It can only ever navigate to /authorize on this origin,
// which validates everything, so this is not an open redirect.
function getOidcRedirectUrl() {
    const params = new URLSearchParams(window.location.search);
    const redirect = params.get('redirect');
    if (!redirect) return null;
    const forward = new URLSearchParams();
    for (const [key, value] of params) {
        forward.append(key === 'redirect' ? 'redirect_uri' : key, value);
    }
    if (!forward.has('response_type')) forward.set('response_type', 'code');
    if (!forward.has('scope')) forward.set('scope', 'openid');
    return '/authorize?' + forward.toString();
}

// `path` with this page's query string, so a link between the sign-in pages
// keeps the authorization request. Only ever a same-origin path.
function withAuthRequest(path) {
    return path + window.location.search;
}

// Where to go once this browser has a session: back into the app's
// authorization request when there is one, otherwise the account page.
function continueAfterSignIn() {
    window.location.href = getOidcRedirectUrl() || '/profile.html';
}

// Public facts about this deployment (GET /api/instance): whether sign-up
// is open and who to contact for help. Fetched once per page. A failure
// resolves to "registration open, no contact" — the server still refuses a
// sign-up it does not allow, so guessing open only risks showing a link.
let instanceInfoPromise = null;
function loadInstanceInfo() {
    if (!instanceInfoPromise) {
        instanceInfoPromise = apiGet('/api/instance').catch(() => ({
            registration_enabled: true,
            support_contact: ''
        }));
    }
    return instanceInfoPromise;
}

// Hides every element marked data-requires-registration when sign-up is
// closed on this deployment.
function applyRegistrationVisibility() {
    return loadInstanceInfo().then(info => {
        if (info.registration_enabled === false) {
            document.querySelectorAll('[data-requires-registration]')
                .forEach(node => node.classList.add('hidden'));
        }
        return info;
    });
}

function apiGet(url) {
    return apiRequest('GET', url);
}

function apiPost(url, body) {
    return apiRequest('POST', url, body);
}

function apiPut(url, body) {
    return apiRequest('PUT', url, body);
}

function apiDelete(url) {
    return apiRequest('DELETE', url);
}

function showError(msg) {
    const el = document.getElementById('error-msg');
    if (el) {
        el.textContent = msg;
        el.classList.remove('hidden');
        setTimeout(() => el.classList.add('hidden'), 5000);
    }
}

function showSuccess(msg) {
    const el = document.getElementById('success-msg');
    if (el) {
        el.textContent = msg;
        el.classList.remove('hidden');
        setTimeout(() => el.classList.add('hidden'), 5000);
    }
}

// Escapes text for interpolation into HTML, attribute values included.
//
// The old version was textContent -> innerHTML, which escapes & < > but NOT
// quotes (a text node serialises without them), so a value inside a quoted
// attribute or an inline handler could break out: security audit M1 ran
// script through a server_url in onclick="removeServer('...')". The pages now
// build rows with createElement/textContent and attach listeners with
// addEventListener, so nothing should need this; it is kept, correct, for
// anything that still does.
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Creates an element with optional class and text. Text always goes through
// textContent, never innerHTML.
function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
}

function mutedMessage(text) {
    const p = el('p', 'muted', text);
    return p;
}
