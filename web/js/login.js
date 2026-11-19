// BSFChat ID - sign-in page.
//
// Loaded as a file rather than inline: the pages are served with a CSP whose
// script-src is 'self' (no 'unsafe-inline'), see default_security_headers().

let pendingLoginToken = null;

// Carry the authorization request (if any) over to the sign-up page, so
// "Create one" from the app's sign-in does not strand the app.
document.getElementById('register-link').href = withAuthRequest('/register.html');
applyRegistrationVisibility();
// The forgot-password page links back here, so it keeps the request too.
document.getElementById('forgot-link').href = withAuthRequest('/forgot-password.html');

const pageParams = new URLSearchParams(window.location.search);

// "Sign out everywhere" (and plain sign-out) land here; say it worked.
if (pageParams.get('signed_out') === 'everywhere') {
    showSuccess('You were signed out on every device and app.');
} else if (pageParams.get('signed_out')) {
    showSuccess('You are signed out.');
}

// Already signed in and nothing to continue into: there is nothing to do
// here, so go to the account (or the page that asked). With an app's
// authorization request the page stays: /authorize sends a signed-in
// browser straight to consent, so reaching here means it was not signed in.
if (!getOidcRedirectUrl() && !pageParams.get('signed_out')) {
    apiGet('/api/profile').then(() => continueAfterSignIn()).catch(() => {});
}

// Coming from an app's sign-in (/authorize): say which app, and which chat
// server, so the person knows what they are signing in to.
(function describeRequestingApp() {
    const clientId = pageParams.get('client_id');
    if (!pageParams.get('redirect') || !clientId) return;
    const node = document.getElementById('requesting-app');
    let server = '';
    try {
        const resource = pageParams.get('resource');
        if (resource) server = new URL(resource).host;
    } catch (e) { server = ''; }
    apiGet('/api/authorize/client?client_id=' + encodeURIComponent(clientId)).then(info => {
        node.replaceChildren(document.createTextNode('Sign in to continue to '),
                             el('strong', null, info.name));
        if (server) {
            node.appendChild(document.createTextNode(' and the chat server '));
            node.appendChild(el('strong', null, server));
        }
        node.appendChild(document.createTextNode('.'));
        node.classList.remove('hidden');
    }).catch(() => {});
})();

function showPasswordStep(message) {
    pendingLoginToken = null;
    document.getElementById('2fa-step').classList.add('hidden');
    document.getElementById('login-form').classList.remove('hidden');
    setBackupCodeMode(false, false);
    document.getElementById('password').value = '';
    if (message) showError(message, document.getElementById('login-form'));
    document.getElementById('password').focus();
}

// Step 1: password
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearErrors();
    // Surrounding spaces are an autocomplete artefact, never part of a name.
    // Case is left alone here: the server folds it (see handle_login).
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    try {
        const data = await apiPost('/api/login', { username, password });

        if (data.requires_2fa) {
            // Server didn't create a session yet — need a TOTP code.
            pendingLoginToken = data.login_token;
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('2fa-step').classList.remove('hidden');
            document.getElementById('totp-code').focus();
        } else {
            continueAfterSignIn();
        }
    } catch (err) {
        showError(err.message, e.target);
    }
});

// Step 2: TOTP code
document.getElementById('2fa-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearErrors();
    // Some authenticators show "123 456"; no code contains whitespace.
    const code = document.getElementById('totp-code').value.replace(/\s+/g, '');
    if (!code) return;

    try {
        await apiPost('/api/login/2fa', {
            login_token: pendingLoginToken,
            code: code
        });
        continueAfterSignIn();
    } catch (err) {
        // The login token is gone (expired, or too many wrong codes): no
        // code can work now, so go back to the password (audit 3).
        if (err.data && err.data.restart) {
            showPasswordStep(err.message);
            return;
        }
        showError(err.message, e.target);
    }
});

// Authenticator code (numeric keypad) or backup code (letters and digits).
let usingBackupCode = false;
function setBackupCodeMode(on, focus = true) {
    usingBackupCode = on;
    const input = document.getElementById('totp-code');
    input.inputMode = on ? 'text' : 'numeric';
    input.autocapitalize = on ? 'characters' : 'none';
    input.placeholder = on ? 'XXXXX-XXXXX' : '000000';
    input.value = '';
    document.getElementById('totp-label').textContent = on ? 'Backup code' : 'Authentication code';
    document.getElementById('totp-hint').textContent = on
        ? 'Enter one of the backup codes you saved when you turned on two-factor authentication. For codes in the XXXXX-XXXXX form, letter case and dashes do not matter; type older codes exactly as printed.'
        : 'Enter the 6-digit code from your authenticator app.';
    document.getElementById('backup-code-toggle').textContent = on
        ? 'Use an authenticator code instead'
        : 'Use a backup code instead';
    if (focus) input.focus();
}
document.getElementById('backup-code-toggle').addEventListener('click', () => {
    setBackupCodeMode(!usingBackupCode);
});

document.getElementById('back-to-login').addEventListener('click', () => {
    clearErrors();
    showPasswordStep();
    document.getElementById('username').focus();
});
