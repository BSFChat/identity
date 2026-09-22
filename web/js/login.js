// BSFChat ID - sign-in page.
//
// Loaded as a file rather than inline: the pages are served with a CSP whose
// script-src is 'self' (no 'unsafe-inline'), see default_security_headers().

let pendingLoginToken = null;

// Rebuild the /authorize request this page was sent from, if any.
//
// Every parameter is forwarded as it arrived (only `redirect` is renamed back
// to `redirect_uri`), so a parameter /authorize learns later — nonce,
// resource — survives the trip through the login page without this file
// having to know about it. It can only ever navigate to /authorize on this
// origin, which validates everything, so this is not an open redirect.
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

function onLoginComplete() {
    const oidcUrl = getOidcRedirectUrl();
    window.location.href = oidcUrl || '/profile.html';
}

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
            onLoginComplete();
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
        onLoginComplete();
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
