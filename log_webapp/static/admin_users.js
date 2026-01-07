document.addEventListener('DOMContentLoaded', () => {
    loadUsers();
    
    // Create user
    document.getElementById('createUserBtn').addEventListener('click', async () => {
        const username = document.getElementById('newUsername').value.trim();
        const password = document.getElementById('newPassword').value;
        
        if (!username || !password) {
            alert('Please fill in all fields');
            return;
        }
        
        try {
            const res = await fetch('/api/admin/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            if (!res.ok) {
                const err = await res.json();
                alert(err.description || 'Failed to create user');
                return;
            }
            
            bootstrap.Modal.getInstance(document.getElementById('createUserModal')).hide();
            document.getElementById('createUserForm').reset();
            loadUsers();
        } catch (error) {
            alert('Error creating user: ' + error.message);
        }
    });
    
    // Change password
    document.getElementById('changePasswordBtn').addEventListener('click', async () => {
        const username = document.getElementById('changeUsername').value;
        const password = document.getElementById('changeNewPassword').value;
        
        if (!password) {
            alert('Please enter a new password');
            return;
        }
        
        try {
            const res = await fetch(`/api/admin/users/${username}/password`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            
            if (!res.ok) {
                const err = await res.json();
                alert(err.description || 'Failed to change password');
                return;
            }
            
            bootstrap.Modal.getInstance(document.getElementById('changePasswordModal')).hide();
            loadUsers();
        } catch (error) {
            alert('Error changing password: ' + error.message);
        }
    });
    
    // Delete user
    document.getElementById('deleteUserBtn').addEventListener('click', async () => {
        const username = document.getElementById('deleteUsername').textContent;
        
        try {
            const res = await fetch(`/api/admin/users/${username}`, {
                method: 'DELETE'
            });
            
            if (!res.ok) {
                const err = await res.json();
                alert(err.description || 'Failed to delete user');
                return;
            }
            
            bootstrap.Modal.getInstance(document.getElementById('deleteUserModal')).hide();
            loadUsers();
        } catch (error) {
            alert('Error deleting user: ' + error.message);
        }
    });
    
    // Logout
    document.getElementById('logoutLink').addEventListener('click', async (e) => {
        e.preventDefault();
        try {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/login';
        } catch (error) {
            window.location.href = '/login';
        }
    });
});

async function loadUsers() {
    try {
        const res = await fetch('/api/admin/users');
        if (!res.ok) {
            if (res.status === 401 || res.status === 403) {
                window.location.href = '/login';
                return;
            }
            throw new Error('Failed to load users');
        }
        
        const data = await res.json();
        renderUsers(data.users);
    } catch (error) {
        console.error('Error loading users:', error);
        document.getElementById('usersTableBody').innerHTML = 
            '<tr><td colspan="3" class="text-center text-danger">Error loading users</td></tr>';
    }
}

function renderUsers(users) {
    const tbody = document.getElementById('usersTableBody');
    
    if (users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-center">No users found</td></tr>';
        return;
    }
    
    tbody.innerHTML = users.map(user => `
        <tr>
            <td>${escapeHtml(user.username)}</td>
            <td>
                <span class="badge ${user.password_changed ? 'bg-success' : 'bg-warning'}">
                    ${user.password_changed ? 'Yes' : 'No'}
                </span>
            </td>
            <td>
                <button class="btn btn-sm btn-outline-primary me-2" 
                        onclick="showChangePasswordModal('${escapeHtml(user.username)}')">
                    Change Password
                </button>
                ${user.username !== 'admin' ? `
                    <button class="btn btn-sm btn-outline-danger" 
                            onclick="showDeleteUserModal('${escapeHtml(user.username)}')">
                        Delete
                    </button>
                ` : ''}
            </td>
        </tr>
    `).join('');
}

function showChangePasswordModal(username) {
    document.getElementById('changeUsername').value = username;
    document.getElementById('changeNewPassword').value = '';
    new bootstrap.Modal(document.getElementById('changePasswordModal')).show();
}

function showDeleteUserModal(username) {
    document.getElementById('deleteUsername').textContent = username;
    new bootstrap.Modal(document.getElementById('deleteUserModal')).show();
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
