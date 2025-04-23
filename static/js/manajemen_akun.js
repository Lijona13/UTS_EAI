// static/js/manajemen_akun.js
document.addEventListener('DOMContentLoaded', function() {
    const usersTableContainer = document.getElementById('users-table-container');
    const formTambahUser = document.getElementById('form-tambah-user');
    const formEditUser = document.getElementById('form-edit-user');
    const tambahUserFeedback = document.getElementById('tambah-user-feedback');
    const editUserFeedback = document.getElementById('edit-user-feedback');
    
    // Bootstrap modals
    const modalTambahUser = new bootstrap.Modal(document.getElementById('modalTambahUser'));
    const modalEditUser = new bootstrap.Modal(document.getElementById('modalEditUser'));

    // --- Helper Functions ---
    function createSpinner(message = 'Loading...', small = false) {
        const sizeClass = small ? 'spinner-border-sm' : '';
        return `<div class="d-flex justify-content-center align-items-center text-secondary my-3">
            <div class="spinner-border ${sizeClass}" role="status">
                <span class="visually-hidden">${message}</span>
            </div>
            <span class="ms-2">${message}</span>
        </div>`;
    }

    function createAlert(message, type = 'info', dismissible = true) {
        const dismissBtn = dismissible ? '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>' : '';
        return `<div class="alert alert-${type} alert-dismissible fade show" role="alert">${message}${dismissBtn}</div>`;
    }

    function showFeedback(element, message, type = 'info') {
        if (element) {
            element.innerHTML = createAlert(message, type);
        }
    }

    function clearFeedback(element) {
        if (element) {
            element.innerHTML = '';
        }
    }

    // --- Load Users Table ---
    function loadUsers() {
        if (!usersTableContainer) return;
        usersTableContainer.innerHTML = createSpinner('Memuat data pengguna...');

        fetch('/api/users')
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => Promise.reject(err.error || `HTTP error! status: ${response.status}`));
                }
                return response.json();
            })
            .then(users => {
                displayUsersTable(users);
            })
            .catch(error => {
                console.error('Error loading users:', error);
                usersTableContainer.innerHTML = createAlert(`Gagal memuat data pengguna: ${error}`, 'danger');
            });
    }

    // --- Display Users Table ---
    function displayUsersTable(users) {
        if (!users || users.length === 0) {
            usersTableContainer.innerHTML = createAlert('Belum ada pengguna terdaftar.', 'info');
            return;
        }

        let tableHTML = `
            <table class="table table-striped table-hover table-sm">
                <thead class="table-light">
                    <tr>
                        <th>Username</th>
                        <th>Nama Lengkap</th>
                        <th>Role</th>
                        <th>Aksi</th>
                    </tr>
                </thead>
                <tbody>`;

        users.forEach(user => {
            const roleBadgeClass = {
                'admin': 'danger',
                'manajer': 'primary',
                'operator': 'success'
            }[user.role] || 'secondary';

            tableHTML += `
                <tr>
                    <td><code>${user.username}</code></td>
                    <td>${user.name || '-'}</td>
                    <td><span class="badge bg-${roleBadgeClass}">${user.role}</span></td>
                    <td>
                        <button class="btn btn-sm btn-warning" onclick="editUser('${user.username}', '${user.name}', '${user.role}')" title="Edit">
                            <i class="bi bi-pencil-square"></i>
                        </button>
                        <button class="btn btn-sm btn-danger" onclick="deleteUser('${user.username}')" title="Hapus">
                            <i class="bi bi-trash"></i>
                        </button>
                    </td>
                </tr>`;
        });

        tableHTML += `</tbody></table>`;
        usersTableContainer.innerHTML = tableHTML;
    }

    // --- Handle Add User Form ---
    if (formTambahUser) {
        formTambahUser.addEventListener('submit', function(event) {
            event.preventDefault();
            clearFeedback(tambahUserFeedback);
            tambahUserFeedback.innerHTML = createSpinner('Menyimpan...', true);

            const formData = new FormData(formTambahUser);
            const data = Object.fromEntries(formData.entries());

            fetch('/api/users', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => Promise.reject(err.error || `Error ${response.status}`));
                }
                return response.json();
            })
            .then(newUser => {
                showFeedback(tambahUserFeedback, `Pengguna baru "${newUser.username}" berhasil ditambahkan!`, 'success');
                formTambahUser.reset();
                loadUsers();
                setTimeout(() => modalTambahUser.hide(), 1500);
            })
            .catch(error => {
                console.error('Error adding user:', error);
                showFeedback(tambahUserFeedback, `Gagal menambahkan pengguna: ${error}`, 'danger');
            });
        });
    }

    // --- Handle Edit User Form ---
    if (formEditUser) {
        formEditUser.addEventListener('submit', function(event) {
            event.preventDefault();
            clearFeedback(editUserFeedback);
            editUserFeedback.innerHTML = createSpinner('Menyimpan...', true);

            const formData = new FormData(formEditUser);
            const data = Object.fromEntries(formData.entries());
            const username = data.username;

            // Remove empty password if not changed
            if (!data.password) delete data.password;

            fetch(`/api/users/${username}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data)
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => Promise.reject(err.error || `Error ${response.status}`));
                }
                return response.json();
            })
            .then(updatedUser => {
                showFeedback(editUserFeedback, `Data pengguna "${updatedUser.username}" berhasil diperbarui!`, 'success');
                loadUsers();
                setTimeout(() => modalEditUser.hide(), 1500);
            })
            .catch(error => {
                console.error('Error updating user:', error);
                showFeedback(editUserFeedback, `Gagal memperbarui pengguna: ${error}`, 'danger');
            });
        });
    }

    // --- Global Functions for Edit/Delete ---
    window.editUser = function(username, name, role) {
        document.getElementById('edit_username').value = username;
        document.getElementById('edit_name').value = name;
        document.getElementById('edit_role').value = role;
        document.getElementById('edit_password').value = ''; // Clear password field
        modalEditUser.show();
    };

    window.deleteUser = function(username) {
        if (confirm(`Apakah Anda yakin ingin menghapus pengguna "${username}"?`)) {
            fetch(`/api/users/${username}`, {
                method: 'DELETE'
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => Promise.reject(err.error || `Error ${response.status}`));
                }
                loadUsers();
                alert(`Pengguna "${username}" berhasil dihapus.`);
            })
            .catch(error => {
                console.error('Error deleting user:', error);
                alert(`Gagal menghapus pengguna: ${error}`);
            });
        }
    };

    // --- Initial Load ---
    loadUsers();
}); 