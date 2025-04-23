// static/js/barang_masuk.js
document.addEventListener('DOMContentLoaded', function() {
    const incomingForm = document.getElementById('form-barang-masuk');
    const incomingFeedback = document.getElementById('masuk-form-feedback');
    const recentIncomingContainer = document.getElementById('recent-incoming-transactions');
    const itemIdInput = document.getElementById('item_id_masuk');
    const inventoryDatalist = document.getElementById('inventory_item_ids');

    const addItemForm = document.getElementById('form-tambah-item');
    const addItemFeedback = document.getElementById('tambah-item-feedback');

    // --- Helper Functions ---
    function formatNumber(num) {
        return new Intl.NumberFormat('id-ID').format(num);
    }
    function createSpinner(message = 'Loading...', small = false) {
         const sizeClass = small ? 'spinner-border-sm' : '';
         return `<div class="d-flex justify-content-center align-items-center text-secondary my-3"><div class="spinner-border ${sizeClass}" role="status"><span class="visually-hidden">${message}</span></div><span class="ms-2">${message}</span></div>`;
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

    // --- Load Inventory Items for Datalist ---
    function loadInventoryItems() {
         fetch('/api/inventory')
             .then(response => response.ok ? response.json() : Promise.reject('Failed to load items'))
             .then(items => {
                 if (inventoryDatalist) {
                     inventoryDatalist.innerHTML = ''; // Clear existing options
                     items.forEach(item => {
                         const option = document.createElement('option');
                         option.value = item.id;
                         option.textContent = `${item.name} (Stok: ${item.quantity})`;
                         inventoryDatalist.appendChild(option);
                     });
                 }
             })
             .catch(error => {
                 console.error("Error loading inventory items for datalist:", error);
                 // Optionally show an error message near the input field
             });
    }

    // --- Load Recent Incoming Transactions ---
    function loadRecentIncoming() {
         if (!recentIncomingContainer) return;
         recentIncomingContainer.innerHTML = createSpinner('Memuat riwayat...', true);

        fetch('/api/transactions?type=masuk') // Filter by type=masuk
             .then(response => {
                 if (!response.ok) return response.json().then(err => Promise.reject(err.error || `HTTP error! status: ${response.status}`));
                 return response.json();
             })
             .then(transactions => {
                 displayTransactionsTable(transactions);
             })
             .catch(error => {
                 console.error('Error loading incoming transactions:', error);
                 recentIncomingContainer.innerHTML = createAlert(`Gagal memuat riwayat: ${error}`, 'danger');
             });
    }

    // --- Display Transactions Table ---
    function displayTransactionsTable(transactions) {
        if (!transactions || transactions.length === 0) {
             recentIncomingContainer.innerHTML = createAlert('Belum ada transaksi barang masuk.', 'info');
             return;
        }
        
        // Sort newest first
        transactions.sort((a, b) => b.id - a.id); 

        let tableHTML = `
             <table class="table table-striped table-hover table-sm">
                <thead class="table-light">
                    <tr>
                        <th>ID</th>
                        <th>Item ID</th>
                        <th>Jumlah</th>
                        <th>Oleh</th>
                        <th>Waktu</th>
                        <th>Catatan</th>
                    </tr>
                </thead>
                 <tbody>`;
        
        transactions.slice(0, 10).forEach(tx => { // Display latest 10
            tableHTML += `
                <tr>
                    <td>${tx.id}</td>
                    <td><code>${tx.item_id}</code></td>
                    <td class="text-end">+${formatNumber(tx.quantity)}</td>
                     <td>${tx.user || '-'}</td>
                    <td><small>${tx.timestamp || '-'}</small></td>
                     <td><small>${tx.notes || '-'}</small></td>
                </tr>`;
        });
         tableHTML += `</tbody></table>`;
        recentIncomingContainer.innerHTML = tableHTML;
    }

    // --- Handle Incoming Form Submission ---
    if (incomingForm) {
        incomingForm.addEventListener('submit', function(event) {
            event.preventDefault();
            clearFeedback(incomingFeedback);
            incomingFeedback.innerHTML = createSpinner('Menyimpan...', true);

            const formData = new FormData(incomingForm);
            const data = Object.fromEntries(formData.entries());

             // Client-side validation example (quantity)
             if (parseInt(data.quantity) <= 0) {
                 showFeedback(incomingFeedback, 'Jumlah harus lebih dari 0.', 'warning');
                 return;
             }

            fetch('/api/transactions/incoming', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    // Include CSRF token header if implemented
                },
                body: JSON.stringify(data)
            })
            .then(response => {
                 if (!response.ok) {
                    // Try to parse error message from server
                     return response.json().then(err => Promise.reject(err.error || `Error ${response.status}`));
                 }
                return response.json(); // Success
            })
            .then(newTransaction => {
                showFeedback(incomingFeedback, `Barang masuk (ID: ${newTransaction.id}) untuk item <code>${newTransaction.item_id}</code> sejumlah ${newTransaction.quantity} berhasil dicatat!`, 'success');
                incomingForm.reset();
                // Reload recent transactions and item list
                 loadRecentIncoming();
                 loadInventoryItems(); 
                 // Optionally update stock display if shown elsewhere
            })
            .catch(error => {
                 console.error('Error recording incoming transaction:', error);
                 showFeedback(incomingFeedback, `Gagal mencatat barang masuk: ${error}`, 'danger');
            });
        });
    }
    
     // --- Handle Add Item Form Submission ---
     if (addItemForm) {
         addItemForm.addEventListener('submit', function(event) {
             event.preventDefault();
             clearFeedback(addItemFeedback);
             addItemFeedback.innerHTML = createSpinner('Menyimpan item baru...', true);

             const formData = new FormData(addItemForm);
             const data = Object.fromEntries(formData.entries());

              // Basic client-side validation
             if (parseInt(data.quantity) < 0) {
                  showFeedback(addItemFeedback, 'Jumlah awal tidak boleh negatif.', 'warning');
                  return;
             }
             if (!data.item_id.trim() || !data.name.trim() || !data.category.trim()) {
                  showFeedback(addItemFeedback, 'ID, Nama, dan Kategori tidak boleh kosong.', 'warning');
                  return;
             }

             fetch('/api/inventory', {
                 method: 'POST',
                 headers: { 'Content-Type': 'application/json' },
                 body: JSON.stringify(data)
             })
             .then(response => {
                  if (!response.ok) {
                       return response.json().then(err => Promise.reject(err.error || `Error ${response.status}`));
                  }
                  return response.json();
             })
             .then(newItem => {
                  showFeedback(addItemFeedback, `Item baru <code>${newItem.id}</code> (${newItem.name}) berhasil ditambahkan!`, 'success');
                  addItemForm.reset();
                  loadInventoryItems(); // Refresh datalist on barang masuk form
                  // Optionally, auto-fill the incoming form with the new item ID?
                   if(itemIdInput) itemIdInput.value = newItem.id;
             })
             .catch(error => {
                  console.error('Error adding new item:', error);
                  showFeedback(addItemFeedback, `Gagal menambahkan item: ${error}`, 'danger');
             });
         });
     }

    // --- Initial Loads ---
    loadInventoryItems();
    loadRecentIncoming();

});