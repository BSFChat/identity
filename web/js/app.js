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
