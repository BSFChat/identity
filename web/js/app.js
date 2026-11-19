// BSFChat ID - Shared JavaScript

// What to say when the answer is not this service's JSON: a reverse proxy's
// own error page (nginx's 502 while the service restarts, 413 for a body
// over its limit) or no answer at all. res.json() on those used to surface
// as "Unexpected token '<'".
function friendlyHttpError(status) {
    if (status === 413) return 'That was too large to send.';
    if (status === 429) return 'Too many attempts. Wait a few minutes and try again.';
    if (status === 502 || status === 503 || status === 504) {
        return 'BSFChat ID is not reachable right now. Try again in a moment.';
    }
    if (status >= 500) return `Something went wrong on our side (error ${status}). Try again in a moment.`;
    return `The request could not be completed (error ${status}).`;
}

async function apiRequest(method, url, body) {
    const opts = {
        method,
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        credentials: 'same-origin'
    };
    if (body && method !== 'GET') {
        opts.body = JSON.stringify(body);
    }
    let res;
    try {
        res = await fetch(url, opts);
    } catch (networkError) {
        throw new Error('Could not reach BSFChat ID. Check your connection and try again.');
    }
    let data = null;
    const type = res.headers.get('Content-Type') || '';
    if (type.includes('application/json')) {
        try {
            data = await res.json();
        } catch (parseError) {
            data = null;
        }
    }
    if (!res.ok) {
        const err = new Error((data && data.error) || friendlyHttpError(res.status));
        err.status = res.status;
        err.data = data || {};
        throw err;
    }
    if (data === null) {
        throw new Error('BSFChat ID sent an unexpected answer. Try again in a moment.');
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
// keeps the authorization request (and `next`). Only ever a same-origin path.
function withAuthRequest(path) {
    return path + window.location.search;
}

// The page to return to after signing in, from ?next= (audit 3: a link to
// profile.html#delete lost the #delete across sign-in). Only a same-origin
// path is honoured: it must start with one '/', and carry no backslash or
// scheme, so ?next= cannot become an open redirect.
function safeNextPath() {
    const next = new URLSearchParams(window.location.search).get('next');
    if (!next || next[0] !== '/' || next[1] === '/' || next.includes('\\')) return null;
    try {
        const url = new URL(next, window.location.origin);
        if (url.origin !== window.location.origin) return null;
        return url.pathname + url.search + url.hash;
    } catch (e) {
        return null;
    }
}

// /login.html with ?next= naming the current page, hash included, for a page
// that found it is signed out.
function loginUrlReturningHere() {
    const here = window.location.pathname + window.location.search + window.location.hash;
    return '/login.html?next=' + encodeURIComponent(here);
}

// Where to go once this browser has a session: back into the app's
// authorization request when there is one, else the page that sent us here,
// otherwise the account page.
function continueAfterSignIn() {
    window.location.href = getOidcRedirectUrl() || safeNextPath() || '/profile.html';
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

// Banners. Both are live regions in the markup (role="alert" for errors,
// role="status" for success), so a screen reader announces them. An error
// stays until the next message replaces it — it used to vanish after five
// seconds, often before it was read — and is scrolled into view, taking
// focus only when focus is not in a field the user is typing in.
let successTimer = null;

function revealBanner(node) {
    node.classList.remove('hidden');
    node.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

// The error box for `anchor` (a form or section), created on first use as
// its first child, so an error shows next to what caused it (audit 3: it
// used to appear at the top of the page, far from the form). Without an
// anchor, the page's #error-msg banner.
function errorNodeFor(anchor) {
    if (!anchor) return document.getElementById('error-msg');
    let node = anchor.querySelector(':scope > .form-error');
    if (!node) {
        node = el('div', 'error form-error hidden');
        node.setAttribute('role', 'alert');
        node.tabIndex = -1;
        anchor.prepend(node);
    }
    return node;
}

function showError(msg, anchor) {
    const node = errorNodeFor(anchor);
    if (!node) return;
    clearErrors();
    const success = document.getElementById('success-msg');
    if (success) success.classList.add('hidden');
    node.textContent = msg;
    revealBanner(node);
    const active = document.activeElement;
    const typing = active && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA');
    if (!typing) node.focus({ preventScroll: true });
}

// Hides every error on the page: the banner and each form's own.
function clearErrors() {
    document.querySelectorAll('#error-msg, .form-error').forEach(node => node.classList.add('hidden'));
}

// Kept for the pages that call it by its old name.
function clearError() {
    clearErrors();
}

function showSuccess(msg) {
    const node = document.getElementById('success-msg');
    if (!node) return;
    clearErrors();
    node.textContent = msg;
    revealBanner(node);
    clearTimeout(successTimer);
    successTimer = setTimeout(() => node.classList.add('hidden'), 8000);
}

// Signs out (this browser, or everywhere) and goes to the sign-in page,
// which confirms it.
async function signOut(everywhere) {
    try { await apiPost('/api/logout', everywhere ? { everywhere: true } : {}); } catch (err) { /* ignore */ }
    window.location.href = '/login.html?signed_out=' + (everywhere ? 'everywhere' : '1');
}

// Copies text to the clipboard, falling back to selecting it.
async function copyText(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (e) {
        return false;
    }
}

// Offers `text` as a downloaded file.
function downloadText(filename, text) {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = el('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
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
