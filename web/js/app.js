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

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
