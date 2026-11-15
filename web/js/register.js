// BSFChat ID - registration page. See login.js for why this is a file.

// Back to sign-in without losing the authorization request (see app.js).
document.getElementById('login-link').href = withAuthRequest('/login.html');

// Usernames are lowercase by grammar (the server refuses uppercase rather
// than folding it), so fold as the user types instead of failing the submit.
const usernameInput = document.getElementById('username');
usernameInput.addEventListener('input', () => {
    const lower = usernameInput.value.toLowerCase();
    if (lower !== usernameInput.value) {
        const caret = usernameInput.selectionStart;
        usernameInput.value = lower;
        usernameInput.setSelectionRange(caret, caret);
    }
});

// Say so up front on a deployment with sign-up closed, instead of letting
// someone fill the form in only to be refused.
loadInstanceInfo().then(info => {
    if (info.registration_enabled === false) {
        document.getElementById('register-form').classList.add('hidden');
        document.getElementById('registration-closed').classList.remove('hidden');
    }
});

document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearError();
    const username = document.getElementById('username').value.trim().toLowerCase();
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
