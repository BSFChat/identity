// BSFChat ID - landing page. See login.js for why this is a file.

applyRegistrationVisibility();

// Someone already signed in is offered their account rather than a second
// sign-in. A 401 (the usual case) just leaves the page as it is.
apiGet('/api/profile').then(profile => {
    const action = document.getElementById('primary-action');
    action.textContent = 'Go to your account';
    action.href = '/profile.html';
    document.querySelectorAll('[data-requires-registration]')
        .forEach(node => node.classList.add('hidden'));
}).catch(() => {});
