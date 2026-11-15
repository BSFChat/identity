// BSFChat ID - sign-in page.
//
// Loaded as a file rather than inline: the pages are served with a CSP whose
// script-src is 'self' (no 'unsafe-inline'), see default_security_headers().

let pendingLoginToken = null;

// Carry the authorization request (if any) over to the sign-up page, so
// "Create one" from the app's sign-in does not strand the app.
document.getElementById('register-link').href = withAuthRequest('/register.html');
applyRegistrationVisibility();

// Step 1: password
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
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
    const code = document.getElementById('totp-code').value.trim();
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

// Back link
document.getElementById('back-to-login').addEventListener('click', (e) => {
    e.preventDefault();
    pendingLoginToken = null;
    document.getElementById('2fa-step').classList.add('hidden');
    document.getElementById('login-form').classList.remove('hidden');
    document.getElementById('totp-code').value = '';
});
