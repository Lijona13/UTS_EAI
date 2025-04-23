// static/js/inventory.js
document.addEventListener('DOMContentLoaded', function() {
    const inventoryContainer = document.getElementById('inventory-list-container');

     // Fungsi format Angka (opsional)
    function formatNumber(num) {
        return new Intl.NumberFormat('id-ID').format(num);
    }
    
     // Fungsi membuat elemen spinner Bootstrap
    function createSpinner(message = 'Loading...') {
        return `
            <div class="d-flex justify-content-center align-items-center text-secondary mt-5">
                <div class="spinner-border" role="status">
                    <span class="visually-hidden">${message}</span>
                </div>
                <span class="ms-2">${message}</span>
            </div>`;
    }

    // Fungsi membuat elemen alert Bootstrap
    function createAlert(message, type = 'info') {
        return `<div class="alert alert-${type}" role="alert">${message}</div>`;
    }

    function loadInventory() {
        if (!inventoryContainer) {
             console.error("Inventory container not found!");
             return;
        }
        inventoryContainer.innerHTML = createSpinner('Memuat daftar inventaris...');

        fetch('/api/inventory')
            .then(response => {
                 if (!response.ok) {
                    if (response.status === 403) throw new Error('Akses ditolak (403)');
                     return response.json().then(err => { throw new Error(err.error || `HTTP error! status: ${response.status}`) });
                }
                return response.json();
            })
            .then(inventory => {
                displayInventoryTable(inventory);
            })
            .catch(error => {
                console.error('Error loading inventory:', error);
                 inventoryContainer.innerHTML = createAlert(`Gagal memuat inventaris: ${error.message}`, 'danger');
            });
    }

    function displayInventoryTable(inventory) {
         if (!inventory || inventory.length === 0) {
            inventoryContainer.innerHTML = createAlert('Tidak ada item dalam inventaris.', 'warning');
            return;
        }

        let tableHTML = `
            <table class="table table-striped table-hover table-bordered table-sm">
                <thead class="table-dark">
                     <tr>
                        <th>ID Item</th>
                        <th>Nama Item</th>
                        <th>Kategori</th>
                        <th class="text-end">Jumlah Stok</th>
                        <th>Ditambahkan Oleh</th>
                         <th>Update Terakhir</th>
                         </tr>
                </thead>
                <tbody>
        `;

        // Urutkan berdasarkan ID Item (opsional)
        inventory.sort((a, b) => a.id.localeCompare(b.id)); 

        inventory.forEach(item => {
             const quantityClass = item.quantity <= 5 ? 'text-danger fw-bold' : (item.quantity <= 10 ? 'text-warning' : '');
             tableHTML += `
                <tr>
                    <td><code>${item.id}</code></td>
                    <td>${item.name}</td>
                    <td>${item.category || '-'}</td>
                    <td class="text-end ${quantityClass}">${formatNumber(item.quantity)}</td>
                    <td>${item.added_by || '-'}</td>
                    <td><small>${item.last_update || '-'}</small></td>
                     </tr>
            `;
        });

         tableHTML += `
                </tbody>
            </table>
        `;
        inventoryContainer.innerHTML = tableHTML;
    }

    // Initial load
    loadInventory();

    // TODO: Implementasi fungsi untuk Tambah/Edit/Hapus Item jika modal ada di halaman ini
});