// BSFChat ID - admin page. DOM-built rows and addEventListener only; see
// profile.js for why.

function cell(text) {
    return el('td', null, text);
}

// Not signed in: sign in and come back. Signed in but not an administrator:
// the account page. Decided on the HTTP status (audit 3: it used to look
// for "403" in the message text, which never contains it).
function handleAdminAuthError(err) {
    if (err.status === 401) {
        window.location.href = loginUrlReturningHere();
        return true;
    }
    if (err.status === 403) {
        window.location.href = '/profile.html';
        return true;
    }
    return false;
}

// The signed-in administrator's own id, so their row offers no Disable
// (the server refuses it anyway).
let myUserId = null;

async function loadUsers() {
    try {
        if (myUserId === null) myUserId = (await apiGet('/api/profile')).user_id;
        const data = await apiGet('/api/admin/users');
        const tbody = document.getElementById('users-body');
        tbody.replaceChildren();
        for (const user of data.users) {
            const tr = document.createElement('tr');
            tr.appendChild(cell(user.username));
            tr.appendChild(cell(user.email || ''));
            tr.appendChild(cell(user.display_name || ''));
            tr.appendChild(cell(user.is_admin ? 'Yes' : 'No'));
            tr.appendChild(cell(new Date(user.created_at * 1000).toLocaleDateString()));
            const actions = document.createElement('td');
            if (user.deleted) {
                // A tombstone: the name is reserved, nothing else is left,
                // and it cannot be re-enabled.
                actions.appendChild(el('span', 'status-badge disabled', 'Deleted'));
            } else if (user.id === myUserId) {
                actions.appendChild(el('span', 'muted', 'You'));
            } else {
                const btn = el('button', 'btn btn-small ' + (user.disabled ? 'btn-secondary' : 'btn-danger'),
                               user.disabled ? 'Enable' : 'Disable');
                btn.type = 'button';
                btn.addEventListener('click', () => setUserEnabled(user.id, user.disabled));
                if (user.disabled) actions.appendChild(el('span', 'status-badge disabled', 'Disabled'));
                actions.appendChild(btn);
            }
            tr.appendChild(actions);
            tbody.appendChild(tr);
        }
    } catch (err) {
        if (!handleAdminAuthError(err)) showError(err.message, document.getElementById('users-section'));
    }
}

async function loadClients() {
    try {
        const data = await apiGet('/api/admin/clients');
        const tbody = document.getElementById('clients-body');
        tbody.replaceChildren();
        for (const client of data.clients) {
            const tr = document.createElement('tr');
            const id = document.createElement('td');
            id.appendChild(el('code', null, client.client_id));
            tr.appendChild(id);
            tr.appendChild(cell(client.name));
            tr.appendChild(cell(client.redirect_uris));
            tr.appendChild(cell(new Date(client.created_at * 1000).toLocaleDateString()));
            tbody.appendChild(tr);
        }
    } catch (err) {
        if (!handleAdminAuthError(err)) showError(err.message, document.getElementById('clients-section'));
    }
}

async function setUserEnabled(userId, enable) {
    const question = enable
        ? 'Re-enable this user? They can sign in again with their existing password.'
        : 'Disable this user? Every session and signed-in app they have is ended immediately.';
    if (!confirm(question)) return;
    try {
        await apiPost(`/api/admin/users/${encodeURIComponent(userId)}/${enable ? 'enable' : 'disable'}`, {});
        loadUsers();
    } catch (err) {
        if (!handleAdminAuthError(err)) showError(err.message, document.getElementById('users-section'));
    }
}

document.getElementById('client-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
        const result = await apiPost('/api/admin/clients', {
            name: document.getElementById('client-name').value,
            redirect_uris: document.getElementById('client-uris').value
        });
        document.getElementById('client-result').classList.remove('hidden');
        document.getElementById('client-result-json').textContent = JSON.stringify(result, null, 2);
        loadClients();
    } catch (err) {
        if (!handleAdminAuthError(err)) showError(err.message, e.target);
    }
});

document.getElementById('logout-btn').addEventListener('click', () => signOut(false));

loadUsers();
loadClients();
