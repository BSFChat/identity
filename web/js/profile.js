// BSFChat ID - account page.
//
// No inline script and no inline event handlers: rows are built with
// createElement/textContent and listeners are attached with addEventListener,
// capturing values in closures. Security audit M1 was exactly the pattern
// this replaces — a server_url interpolated into onclick="removeServer('...')"
// ran as script — and the page is now served with a CSP that would refuse an
// inline handler even if one crept back in.

// ---- Tab switching ----
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
        // Lazy-load tab data
        if (btn.dataset.tab === 'sessions') { loadSessions(); loadApps(); }
        if (btn.dataset.tab === 'security') load2FAStatus();
        if (btn.dataset.tab === 'servers') loadServers();
    });
});

function button(label, className, onClick) {
    const b = el('button', 'btn btn-small ' + className, label);
    b.type = 'button';
    b.addEventListener('click', onClick);
    return b;
}

function signedOutNotice(prefix, count) {
    if (count > 0) {
        return `${prefix} ${count} other session${count === 1 ? '' : 's'} or app${count === 1 ? '' : 's'} were signed out.`;
    }
    return prefix;
}

// ---- Profile tab ----
async function loadProfile() {
    try {
        const profile = await apiGet('/api/profile');
        document.getElementById('username').value = profile.username;
        document.getElementById('display_name').value = profile.display_name || '';
        document.getElementById('email').value = profile.email || '';
        document.getElementById('avatar_url').value = profile.avatar_url || '';
        if (profile.is_admin) {
            document.getElementById('admin-link').classList.remove('hidden');
        }
    } catch (err) {
        window.location.href = '/login.html';
    }
}

document.getElementById('profile-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
        await apiPut('/api/profile', {
            display_name: document.getElementById('display_name').value,
            email: document.getElementById('email').value,
            avatar_url: document.getElementById('avatar_url').value
        });
        showSuccess('Profile updated successfully');
    } catch (err) {
        showError(err.message);
    }
});

// ---- Security tab: password ----
document.getElementById('password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
        const data = await apiPut('/api/profile', {
            old_password: document.getElementById('old_password').value,
            new_password: document.getElementById('new_password').value
        });
        showSuccess(signedOutNotice('Password changed.', data.signed_out_elsewhere || 0));
        document.getElementById('old_password').value = '';
        document.getElementById('new_password').value = '';
    } catch (err) {
        showError(err.message);
    }
});

// ---- Security tab: 2FA ----
async function load2FAStatus() {
    const area = document.getElementById('2fa-status-area');
    try {
        const data = await apiGet('/api/user/2fa/status');
        const row = el('div', 'status-row');
        row.style.display = 'flex';
        row.style.alignItems = 'center';
        row.style.justifyContent = 'space-between';
        if (data.enabled) {
            row.appendChild(el('span', 'status-badge enabled', '✓ Enabled'));
            row.appendChild(button('Disable 2FA', 'btn-danger', disable2FA));
        } else {
            row.appendChild(el('span', 'status-badge disabled', 'Not enabled'));
            row.appendChild(button('Enable 2FA', 'btn-primary', setup2FA));
        }
        area.replaceChildren(row);
    } catch (err) {
        area.replaceChildren(mutedMessage('Could not load 2FA status.'));
    }
}

async function setup2FA() {
    try {
        const data = await apiPost('/api/user/2fa/setup', {});

        // Show setup area
        document.getElementById('2fa-status-area').classList.add('hidden');
        document.getElementById('2fa-setup-area').classList.remove('hidden');

        // Secret for manual entry
        document.getElementById('2fa-secret-display').textContent = data.secret;

        // QR code (qrcode.min.js renders into a canvas and a data: image,
        // which the CSP's img-src allows).
        const qrTarget = document.getElementById('qr-target');
        qrTarget.replaceChildren();
        if (typeof QRCode !== 'undefined') {
            new QRCode(qrTarget, {
                text: data.provisioning_uri,
                width: 160,
                height: 160,
                colorDark: '#000',
                colorLight: '#fff',
                correctLevel: QRCode.CorrectLevel.M
            });
        } else {
            qrTarget.textContent = data.provisioning_uri;
        }

        // Backup codes
        const grid = document.getElementById('backup-codes-grid');
        grid.replaceChildren();
        (data.backup_codes || []).forEach(code => {
            grid.appendChild(el('code', null, code));
        });
    } catch (err) {
        showError(err.message);
    }
}

async function verify2FA() {
    const code = document.getElementById('2fa-verify-code').value.trim();
    if (code.length !== 6) { showError('Enter a 6-digit code'); return; }
    try {
        const data = await apiPost('/api/user/2fa/verify', { code });
        showSuccess(signedOutNotice('Two-factor authentication enabled.', data.signed_out_elsewhere || 0));
        cancel2FASetup();
        load2FAStatus();
    } catch (err) {
        showError(err.message);
    }
}

function cancel2FASetup() {
    document.getElementById('2fa-setup-area').classList.add('hidden');
    document.getElementById('2fa-status-area').classList.remove('hidden');
    document.getElementById('2fa-verify-code').value = '';
}

async function disable2FA() {
    const password = prompt('Enter your password to disable 2FA:');
    if (!password) return;
    try {
        const data = await apiPost('/api/user/2fa/disable', { password });
        showSuccess(signedOutNotice('Two-factor authentication disabled.', data.signed_out_elsewhere || 0));
        load2FAStatus();
    } catch (err) {
        showError(err.message);
    }
}

document.getElementById('2fa-verify-btn').addEventListener('click', verify2FA);
document.getElementById('2fa-cancel-btn').addEventListener('click', cancel2FASetup);

// ---- Sessions tab ----
async function loadSessions() {
    const container = document.getElementById('sessions-list');
    try {
        const sessions = await apiGet('/api/user/sessions');
        if (sessions.length === 0) {
            container.replaceChildren(mutedMessage('No active sessions.'));
            return;
        }
        container.replaceChildren();
        sessions.forEach(s => {
            const created = new Date(s.created_at * 1000).toLocaleString();
            const expires = new Date(s.expires_at * 1000).toLocaleString();
            const row = el('div', 'session-row' + (s.is_current ? ' current' : ''));
            const info = el('div', 'session-info');
            const title = el('div', 'session-id', s.is_current ? 'This browser' : 'Browser session');
            if (s.is_current) title.appendChild(el('span', 'session-badge', 'Current'));
            info.appendChild(title);
            info.appendChild(el('div', 'session-time', `Created ${created} • Expires ${expires}`));
            row.appendChild(info);
            if (!s.is_current) {
                // s.session_id is an opaque handle the server resolves within
                // this account's own sessions (security audit M3).
                row.appendChild(button('Revoke', 'btn-danger', () => revokeSession(s.session_id)));
            }
            container.appendChild(row);
        });
    } catch (err) {
        container.replaceChildren(mutedMessage('Could not load sessions.'));
    }
}

async function revokeSession(handle) {
    try {
        await apiDelete('/api/user/sessions/' + encodeURIComponent(handle));
        showSuccess('Session revoked');
        loadSessions();
    } catch (err) {
        showError(err.message);
    }
}

async function loadApps() {
    const container = document.getElementById('apps-list');
    try {
        const apps = await apiGet('/api/user/apps');
        if (apps.length === 0) {
            container.replaceChildren(mutedMessage('No apps are signed in.'));
            return;
        }
        container.replaceChildren();
        apps.forEach(a => {
            const created = new Date(a.created_at * 1000).toLocaleString();
            const until = new Date(a.absolute_expires_at * 1000).toLocaleDateString();
            const row = el('div', 'session-row');
            const info = el('div', 'session-info');
            info.appendChild(el('div', 'session-id', a.client_name || a.client_id));
            info.appendChild(el('div', 'session-time',
                `Signed in ${created} • Must sign in again by ${until}`));
            row.appendChild(info);
            row.appendChild(button('Revoke', 'btn-danger', () => revokeApp(a.id)));
            container.appendChild(row);
        });
    } catch (err) {
        container.replaceChildren(mutedMessage('Could not load apps.'));
    }
}

async function revokeApp(id) {
    if (!confirm('Sign this app out? It will ask you to sign in again.')) return;
    try {
        await apiDelete('/api/user/apps/' + encodeURIComponent(id));
        showSuccess('App signed out');
        loadApps();
    } catch (err) {
        showError(err.message);
    }
}

document.getElementById('signout-everywhere-btn').addEventListener('click', async () => {
    if (!confirm('Sign out of every session and app, including this browser?')) return;
    try { await apiPost('/api/logout', { everywhere: true }); } catch (err) { /* ignore */ }
    window.location.href = '/login.html';
});

// ---- Servers tab ----
async function loadServers() {
    const container = document.getElementById('servers-list');
    try {
        const servers = await apiGet('/api/servers');
        if (servers.length === 0) {
            container.replaceChildren(mutedMessage(
                'No servers registered yet. Add one below or connect via the BSFChat client.'));
            return;
        }
        container.replaceChildren();
        servers.forEach(s => {
            const joined = new Date(s.joined_at * 1000).toLocaleDateString();
            const row = el('div', 'session-row');
            const info = el('div', 'session-info');
            const name = el('div', 'server-name', s.server_name || s.server_url);
            name.style.fontWeight = '600';
            name.style.color = 'var(--text-primary)';
            info.appendChild(name);
            info.appendChild(el('div', 'session-time', `${s.server_url} • Joined ${joined}`));
            row.appendChild(info);
            // The URL is captured by the closure; it is never parsed as code.
            row.appendChild(button('Remove', 'btn-danger', () => removeServer(s.server_url)));
            container.appendChild(row);
        });
    } catch (err) {
        container.replaceChildren(mutedMessage('Could not load servers.'));
    }
}

async function addServer() {
    const url = document.getElementById('new-server-url').value.trim();
    if (!url) { showError('Enter a server URL'); return; }
    const name = document.getElementById('new-server-name').value.trim();
    try {
        await apiPost('/api/servers', { server_url: url, server_name: name });
        showSuccess('Server added');
        document.getElementById('new-server-url').value = '';
        document.getElementById('new-server-name').value = '';
        loadServers();
    } catch (err) {
        showError(err.message);
    }
}

async function removeServer(serverUrl) {
    if (!confirm('Remove this server from your account?')) return;
    try {
        await apiPost('/api/servers/remove', { server_url: serverUrl });
        showSuccess('Server removed');
        loadServers();
    } catch (err) {
        showError(err.message);
    }
}

document.getElementById('add-server-btn').addEventListener('click', addServer);

// ---- Logout ----
document.getElementById('logout-btn').addEventListener('click', async (e) => {
    e.preventDefault();
    try { await apiPost('/api/logout', {}); } catch (err) { /* ignore */ }
    window.location.href = '/login.html';
});

// ---- Init ----
loadProfile();
