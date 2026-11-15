// BSFChat ID - registration page. See login.js for why this is a file.

// Back to sign-in without losing the authorization request (see app.js).
document.getElementById('login-link').href = withAuthRequest('/login.html');

document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    if (password !== confirmPassword) {
        showError('Passwords do not match');
        return;
    }

    try {
        // /register answers like /api/login: it creates the browser session
        // and sets the cookie, so the new account is already signed in and
        // the app's sign-in can resume straight away.
        await apiPost('/register', { username, password, email });
        continueAfterSignIn();
    } catch (err) {
        showError(err.message);
    }
});
