// BSFChat ID - admin page. DOM-built rows and addEventListener only; see
// profile.js for why.

function cell(text) {
    return el('td', null, text);
}

async function loadUsers() {
    try {
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
            const btn = el('button', 'btn btn-small ' + (user.disabled ? 'btn-secondary' : 'btn-danger'),
                           user.disabled ? 'Enable' : 'Disable');
            btn.type = 'button';
            btn.addEventListener('click', () => setUserEnabled(user.id, user.disabled));
            if (user.disabled) actions.appendChild(el('span', 'status-badge disabled', 'Disabled'));
            actions.appendChild(btn);
            tr.appendChild(actions);
            tbody.appendChild(tr);
        }
    } catch (err) {
        if (err.message.includes('403') || err.message.includes('401')) {
            window.location.href = '/login.html';
        }
        showError(err.message);
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
        showError(err.message);
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
        showError(err.message);
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
        showError(err.message);
    }
});

document.getElementById('logout-btn').addEventListener('click', async (e) => {
    e.preventDefault();
    try { await apiPost('/api/logout', {}); } catch (err) { /* ignore */ }
    window.location.href = '/login.html';
});

loadUsers();
loadClients();
