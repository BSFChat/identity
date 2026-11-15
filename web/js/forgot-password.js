// BSFChat ID - forgot-password page. See login.js for why this is a file.

document.getElementById('login-link').href = withAuthRequest('/login.html');

// Turns the operator's support_contact into a link only when it is plainly
// an email address or an https URL; anything else is shown as text. Built
// with createElement/textContent, never innerHTML.
function contactNode(contact) {
    if (/^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+$/.test(contact)) {
        const a = el('a', null, contact);
        a.href = 'mailto:' + contact;
        return a;
    }
    if (/^https:\/\/[^\s<>"]+$/i.test(contact)) {
        const a = el('a', null, contact);
        a.href = contact;
        a.rel = 'noopener noreferrer';
        return a;
    }
    return el('strong', null, contact);
}

loadInstanceInfo().then(info => {
    const contact = (info.support_contact || '').trim();
    if (!contact) return;
    document.getElementById('support-contact').replaceChildren(contactNode(contact));
    document.getElementById('support-generic').classList.add('hidden');
    document.getElementById('support-specific').classList.remove('hidden');
});
