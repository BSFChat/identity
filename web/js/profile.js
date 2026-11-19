// BSFChat ID - account page.
//
// No inline script and no inline event handlers: rows are built with
// createElement/textContent and listeners are attached with addEventListener,
// capturing values in closures. Security audit M1 was exactly the pattern
// this replaces — a server_url interpolated into onclick="removeServer('...')"
// ran as script — and the page is now served with a CSP that would refuse an
// inline handler even if one crept back in.

const $ = (id) => document.getElementById(id);

// ---- Tabs (WAI-ARIA tabs pattern) and #fragments ----
//
// Each tab is addressable: profile.html#security, #sessions, #servers, and
// #delete (the profile tab, scrolled to account deletion). A link to one
// survives sign-in because the login page is sent here with ?next= (audit 3).

const tabButtons = Array.from(document.querySelectorAll('[role="tab"]'));
const hashTargets = { profile: 'profile', security: 'security', 'two-factor': 'security',
                      sessions: 'sessions', servers: 'servers', delete: 'profile' };

function activateTab(name, { focus = false, updateHash = true } = {}) {
    clearErrors();
    tabButtons.forEach(btn => {
        const selected = btn.dataset.tab === name;
        btn.classList.toggle('active', selected);
        btn.setAttribute('aria-selected', selected ? 'true' : 'false');
        btn.tabIndex = selected ? 0 : -1;
        $('tab-' + btn.dataset.tab).classList.toggle('active', selected);
        if (selected && focus) btn.focus();
    });
    if (updateHash && window.location.hash.slice(1) !== name) {
        history.replaceState(null, '', '#' + name);
    }
    // Lazy-load tab data
    if (name === 'sessions') { loadSessions(); loadApps(); }
    if (name === 'security') load2FAStatus();
    if (name === 'servers') loadServers();
    if (name === 'profile') prepareDeleteForm();
}

function showHash() {
    const hash = decodeURIComponent(window.location.hash.slice(1));
    const tab = hashTargets[hash];
    if (!tab) return false;
    activateTab(tab, { updateHash: false });
    if (hash === 'delete' || hash === 'two-factor') {
        const target = $(hash);
        if (target) target.scrollIntoView({ block: 'start' });
    }
    return true;
}

tabButtons.forEach((btn, index) => {
    btn.addEventListener('click', () => activateTab(btn.dataset.tab));
    btn.addEventListener('keydown', (e) => {
        let next = null;
        if (e.key === 'ArrowRight') next = (index + 1) % tabButtons.length;
        else if (e.key === 'ArrowLeft') next = (index - 1 + tabButtons.length) % tabButtons.length;
        else if (e.key === 'Home') next = 0;
        else if (e.key === 'End') next = tabButtons.length - 1;
        if (next === null) return;
        e.preventDefault();
        activateTab(tabButtons[next].dataset.tab, { focus: true });
    });
});
window.addEventListener('hashchange', showHash);

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

// A 401 from any call means the session ended: sign in again and come back
// to this very tab.
function handleAuthError(err) {
    if (err && err.status === 401) {
        window.location.href = loginUrlReturningHere();
        return true;
    }
    return false;
}

// ---- Profile tab ----
let myUsername = '';

async function loadProfile() {
    try {
        const profile = await apiGet('/api/profile');
        myUsername = profile.username;
        $('username').value = profile.username;
        $('display_name').value = profile.display_name || '';
        $('email').value = profile.email || '';
        $('avatar_url').value = profile.avatar_url || '';
        if (profile.is_admin) $('admin-link').classList.remove('hidden');
        return true;
    } catch (err) {
        if (!handleAuthError(err)) window.location.href = loginUrlReturningHere();
        return false;
    }
}

$('profile-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const displayName = $('display_name').value.trim();
    if (!displayName) {
        showError('Display name cannot be empty', e.target);
        $('display_name').focus();
        return;
    }
    try {
        const data = await apiPut('/api/profile', {
            display_name: displayName,
            email: $('email').value.trim(),
            avatar_url: $('avatar_url').value.trim()
        });
        $('display_name').value = data.display_name || '';
        showSuccess('Profile saved.');
    } catch (err) {
        if (!handleAuthError(err)) showError(err.message, e.target);
    }
});

// ---- Profile tab: delete account (audit I-12) ----
let twoFactorEnabled = false;

async function prepareDeleteForm() {
    // The second-factor field follows the current 2FA state (audit 3: it
    // went stale after turning 2FA on or off); the server checks anyway.
    try {
        const data = await apiGet('/api/user/2fa/status');
        twoFactorEnabled = !!data.enabled;
    } catch (err) { /* keep the last known state */ }
    $('delete-code-group').classList.toggle('hidden', !twoFactorEnabled);
    if (!twoFactorEnabled) $('delete-code').value = '';
}

$('delete-account-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const typed = $('delete-confirm-username').value.trim();
    const password = $('delete-password').value;
    const code = $('delete-code').value.trim();
    // Everything that can be checked here is, before the final question
    // (audit 3: the dialog came first, then "type your username").
    if (typed !== myUsername) {
        showError('Type your username exactly to confirm', form);
        $('delete-confirm-username').focus();
        return;
    }
    if (!password) {
        showError('Enter your current password', form);
        $('delete-password').focus();
        return;
    }
    if (twoFactorEnabled && !code) {
        showError('Enter a code from your authenticator app, or a backup code', form);
        $('delete-code').focus();
        return;
    }
    if (!confirm('Delete your BSFChat ID permanently? This cannot be undone.')) return;
    try {
        const data = await apiPost('/api/account/delete', {
            confirm_username: typed,
            password,
            code
        });
        window.location.href = data.redirect || '/account-deleted.html';
    } catch (err) {
        if (handleAuthError(err)) return;
        showError(err.message, form);
        if (/two-factor|authenticator/i.test(err.message)) {
            twoFactorEnabled = true;
            $('delete-code-group').classList.remove('hidden');
        }
    }
});

// ---- Security tab: password ----
$('password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const newPassword = $('new_password').value;
    // There is no reset by email, so a typo here would lock the user out
    // until an operator resets the password (audit I-2).
    if (newPassword !== $('confirm_new_password').value) {
        showError('The new passwords do not match', form);
        $('confirm_new_password').focus();
        return;
    }
    try {
        const data = await apiPut('/api/profile', {
            old_password: $('old_password').value,
            new_password: newPassword
        });
        showSuccess(signedOutNotice('Password changed.', data.signed_out_elsewhere || 0));
        form.reset();
    } catch (err) {
        if (!handleAuthError(err)) showError(err.message, form);
    }
});

// ---- Security tab: 2FA ----
function hideTwoFactorForms() {
    ['2fa-disable-form', 'backup-regen-form'].forEach(id => {
        $(id).classList.add('hidden');
        $(id).reset();
    });
}

async function load2FAStatus() {
    const area = $('2fa-status-area');
    try {
        const data = await apiGet('/api/user/2fa/status');
        twoFactorEnabled = !!data.enabled;
        const row = el('div', 'status-row');
        if (data.enabled) {
            const info = el('div', 'status-info');
            info.appendChild(el('span', 'status-badge enabled', 'Enabled'));
            const left = data.backup_codes_remaining;
            if (typeof left === 'number') {
                info.appendChild(el('span', 'status-note' + (left <= 2 ? ' warning' : ''),
                    `${left} backup code${left === 1 ? '' : 's'} left`));
            }
            row.appendChild(info);
            const actions = el('div', 'btn-row');
            actions.appendChild(button('New backup codes', 'btn-secondary', () => {
                hideTwoFactorForms();
                $('backup-regen-form').classList.remove('hidden');
                $('backup-regen-password').focus();
            }));
            actions.appendChild(button('Turn off 2FA', 'btn-danger', () => {
                hideTwoFactorForms();
                $('2fa-disable-form').classList.remove('hidden');
                $('2fa-disable-password').focus();
            }));
            row.appendChild(actions);
        } else {
            row.appendChild(el('span', 'status-badge disabled', 'Not enabled'));
            row.appendChild(button('Turn on 2FA', 'btn-primary', setup2FA));
        }
        area.replaceChildren(row);
    } catch (err) {
        if (!handleAuthError(err)) area.replaceChildren(mutedMessage('Could not load 2FA status.'));
    }
}

let shownBackupCodes = [];

function showBackupCodes(codes, withDoneButton) {
    shownBackupCodes = codes || [];
    const grid = $('backup-codes-grid');
    grid.replaceChildren();
    shownBackupCodes.forEach(code => grid.appendChild(el('code', null, code)));
    $('backup-done-btn').classList.toggle('hidden', !withDoneButton);
    $('backup-codes-area').classList.remove('hidden');
}

function hideBackupCodes() {
    shownBackupCodes = [];
    $('backup-codes-grid').replaceChildren();
    $('backup-codes-area').classList.add('hidden');
}

$('backup-copy-btn').addEventListener('click', async () => {
    if (await copyText(shownBackupCodes.join('\n'))) {
        showSuccess('Backup codes copied.');
    } else {
        showError('Could not copy. Select the codes and copy them by hand, or download them.',
                  $('backup-codes-area'));
    }
});
$('backup-download-btn').addEventListener('click', () => {
    const text = 'BSFChat ID backup codes for ' + myUsername + '\n' +
                 'Each code works once. Letter case and dashes do not matter.\n\n' +
                 shownBackupCodes.join('\n') + '\n';
    downloadText('bsfchat-id-backup-codes.txt', text);
});
$('backup-done-btn').addEventListener('click', hideBackupCodes);

async function setup2FA() {
    try {
        const data = await apiPost('/api/user/2fa/setup', {});

        hideTwoFactorForms();
        $('2fa-status-area').classList.add('hidden');
        $('2fa-setup-area').classList.remove('hidden');

        // Secret for manual entry, and the same URI as a link: on a phone the
        // authenticator is on the same device, so there is nothing to scan.
        $('2fa-secret-display').textContent = data.secret;
        $('otpauth-link').href = data.provisioning_uri;

        // QR code (qrcode.min.js renders into a canvas and a data: image,
        // which the CSP's img-src allows).
        const qrTarget = $('qr-target');
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

        showBackupCodes(data.backup_codes, false);
        $('2fa-verify-code').focus();
    } catch (err) {
        if (!handleAuthError(err)) showError(err.message, $('two-factor'));
    }
}

$('2fa-verify-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = $('2fa-verify-code').value.replace(/\s+/g, '');
    if (!/^[0-9]{6}$/.test(code)) {
        showError('Enter the 6-digit code your authenticator shows', e.target);
        return;
    }
    try {
        const data = await apiPost('/api/user/2fa/verify', { code });
        showSuccess(signedOutNotice(
            'Two-factor authentication is on. The code you just used cannot be used again; ' +
            'for the next step that asks, wait for a new one.',
            data.signed_out_elsewhere || 0));
        closeSetup();
        load2FAStatus();
        prepareDeleteForm();
    } catch (err) {
        if (!handleAuthError(err)) showError(err.message, e.target);
    }
});

function closeSetup() {
    $('2fa-setup-area').classList.add('hidden');
    $('2fa-status-area').classList.remove('hidden');
    $('2fa-verify-code').value = '';
    hideBackupCodes();
}

// Cancelling an unconfirmed setup leaves nothing enabled; the pending
// secret is simply replaced by the next setup.
$('2fa-cancel-btn').addEventListener('click', closeSetup);

$('2fa-disable-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
        const data = await apiPost('/api/user/2fa/disable', {
            password: $('2fa-disable-password').value,
            code: $('2fa-disable-code').value.trim()
        });
        hideTwoFactorForms();
        showSuccess(signedOutNotice('Two-factor authentication is off.', data.signed_out_elsewhere || 0));
        load2FAStatus();
        prepareDeleteForm();
    } catch (err) {
        if (!handleAuthError(err)) showError(err.message, e.target);
    }
});
$('2fa-disable-cancel').addEventListener('click', hideTwoFactorForms);

$('backup-regen-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
        const data = await apiPost('/api/user/2fa/backup-codes', {
            password: $('backup-regen-password').value,
            code: $('backup-regen-code').value.trim()
        });
        hideTwoFactorForms();
        showBackupCodes(data.backup_codes, true);
        showSuccess('New backup codes are below. The old ones no longer work.');
        load2FAStatus();
    } catch (err) {
        if (!handleAuthError(err)) showError(err.message, e.target);
    }
});
$('backup-regen-cancel').addEventListener('click', hideTwoFactorForms);

// ---- Sessions tab ----
async function loadSessions() {
    const container = $('sessions-list');
    try {
        const sessions = await apiGet('/api/user/sessions');
        if (sessions.length === 0) {
            container.replaceChildren(mutedMessage('No active sessions.'));
            return;
        }
        container.replaceChildren();
        sessions.forEach(s => {
            const created = new Date(s.created_at * 1000).toLocaleString();
            const row = el('div', 'session-row' + (s.is_current ? ' current' : ''));
            const info = el('div', 'session-info');
            const device = s.device || 'Unknown browser';
            const title = el('div', 'session-title', device);
            if (s.is_current) title.appendChild(el('span', 'session-badge', 'This browser'));
            info.appendChild(title);
            const where = s.ip ? ` from ${s.ip}` : '';
            info.appendChild(el('div', 'session-time', `Signed in ${created}${where}`));
            row.appendChild(info);
            if (!s.is_current) {
                // s.session_id is an opaque handle the server resolves within
                // this account's own sessions (security audit M3).
                row.appendChild(button('Revoke', 'btn-danger', () => revokeSession(s.session_id, device)));
            }
            container.appendChild(row);
        });
    } catch (err) {
        if (!handleAuthError(err)) container.replaceChildren(mutedMessage('Could not load sessions.'));
    }
}

async function revokeSession(handle, device) {
    if (!confirm(`Sign out the session "${device}"?`)) return;
    try {
        await apiDelete('/api/user/sessions/' + encodeURIComponent(handle));
        showSuccess('Session signed out.');
        loadSessions();
    } catch (err) {
        if (!handleAuthError(err)) showError(err.message, $('sessions-section'));
    }
}

async function loadApps() {
    const container = $('apps-list');
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
            info.appendChild(el('div', 'session-title', a.client_name || a.client_id));
            info.appendChild(el('div', 'session-time',
                `Signed in ${created} • Must sign in again by ${until}`));
            row.appendChild(info);
            row.appendChild(button('Revoke', 'btn-danger', () => revokeApp(a.id)));
            container.appendChild(row);
        });
    } catch (err) {
        if (!handleAuthError(err)) container.replaceChildren(mutedMessage('Could not load apps.'));
    }
}

async function revokeApp(id) {
    if (!confirm('Sign this app out? It will ask you to sign in again.')) return;
    try {
        await apiDelete('/api/user/apps/' + encodeURIComponent(id));
        showSuccess('App signed out.');
        loadApps();
    } catch (err) {
        if (!handleAuthError(err)) showError(err.message, $('apps-section'));
    }
}

$('signout-everywhere-btn').addEventListener('click', () => {
    if (!confirm('Sign out of every session and app, including this browser?')) return;
    signOut(true);
});

// ---- Servers tab ----
async function loadServers() {
    const container = $('servers-list');
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
            info.appendChild(el('div', 'session-title', s.server_name || s.server_url));
            info.appendChild(el('div', 'session-time', `${s.server_url} • Added ${joined}`));
            row.appendChild(info);
            // The URL is captured by the closure; it is never parsed as code.
            row.appendChild(button('Remove', 'btn-danger', () => removeServer(s.server_url)));
            container.appendChild(row);
        });
    } catch (err) {
        if (!handleAuthError(err)) container.replaceChildren(mutedMessage('Could not load servers.'));
    }
}

$('add-server-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    let url = $('new-server-url').value.trim();
    if (!url) { showError('Enter the server address', form); return; }
    // "chat.example.com" is what people type; the server wants a URL.
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) url = 'https://' + url;
    const name = $('new-server-name').value.trim();
    try {
        await apiPost('/api/servers', { server_url: url, server_name: name });
        showSuccess('Server added.');
        form.reset();
        loadServers();
    } catch (err) {
        if (!handleAuthError(err)) showError(err.message, form);
    }
});

async function removeServer(serverUrl) {
    if (!confirm('Remove this server from your account?')) return;
    try {
        await apiPost('/api/servers/remove', { server_url: serverUrl });
        showSuccess('Server removed.');
        loadServers();
    } catch (err) {
        if (!handleAuthError(err)) showError(err.message, $('servers-list').parentElement);
    }
}

// ---- Sign out ----
$('logout-btn').addEventListener('click', () => signOut(false));

// ---- Init ----
loadProfile().then(ok => {
    if (!ok) return;
    if (!showHash()) prepareDeleteForm();
});
