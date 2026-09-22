// BSFChat ID - registration page. See login.js for why this is a file.

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
        await apiPost('/register', { username, password, email });
        window.location.href = '/profile.html';
    } catch (err) {
        showError(err.message);
    }
});
