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

// Step 1: password
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
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
        showError(err.message);
    }
});

// Step 2: TOTP code
document.getElementById('2fa-form').addEventListener('submit', async (e) => {
    e.preventDefault();
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
        showError(err.message);
    }
});

// Authenticator code (numeric keypad) or backup code (letters and digits).
let usingBackupCode = false;
function setBackupCodeMode(on) {
    usingBackupCode = on;
    const input = document.getElementById('totp-code');
    input.inputMode = on ? 'text' : 'numeric';
    input.placeholder = on ? 'Backup code' : '000000';
    input.value = '';
    document.getElementById('totp-label').textContent = on ? 'Backup Code' : 'Authentication Code';
    document.getElementById('totp-hint').textContent = on
        ? 'Enter one of the backup codes you saved when you turned on two-factor authentication. Letter case matters.'
        : 'Enter the 6-digit code from your authenticator app.';
    document.getElementById('backup-code-toggle').textContent = on
        ? 'Use an authenticator code instead'
        : 'Use a backup code instead';
    input.focus();
}
document.getElementById('backup-code-toggle').addEventListener('click', (e) => {
    e.preventDefault();
    setBackupCodeMode(!usingBackupCode);
});

// Back link
document.getElementById('back-to-login').addEventListener('click', (e) => {
    e.preventDefault();
    pendingLoginToken = null;
    document.getElementById('2fa-step').classList.add('hidden');
    document.getElementById('login-form').classList.remove('hidden');
    setBackupCodeMode(false);
    document.getElementById('username').focus();
});
