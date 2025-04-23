// static/js/barang_keluar.js
document.addEventListener('DOMContentLoaded', function() {
    const outgoingForm = document.getElementById('form-barang-keluar');
    const outgoingFeedback = document.getElementById('keluar-form-feedback');
    const recentOutgoingContainer = document.getElementById('recent-outgoing-transactions');
    const itemIdInput = document.getElementById('item_id_keluar');
    const quantityInput = document.getElementById('quantity_keluar');
    const stockInfo = document.getElementById('stock-info');
    const inventoryDatalist = document.getElementById('inventory_item_ids');

    let currentInventory = {}; // To store inventory data for stock checking

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

    // --- Load Inventory Items for Datalist & Stock Check ---
    function loadInventoryItems() {
        fetch('/api/inventory')
            .then(response => response.ok ? response.json() : Promise.reject('Failed to load items'))
            .then(items => {
                currentInventory = {}; // Reset
                if (inventoryDatalist) {
                    inventoryDatalist.innerHTML = ''; // Clear existing options
                    items.forEach(item => {
                        currentInventory[item.id] = item; // Store item data
                        const option = document.createElement('option');
                        option.value = item.id;
                        option.textContent = `${item.name} (Stok: ${item.quantity})`;
                        inventoryDatalist.appendChild(option);
                    });
                }
                 updateStockInfo(); // Update stock info based on initial/cleared input
            })
            .catch(error => {
                console.error("Error loading inventory items for datalist:", error);
                 if(stockInfo) stockInfo.textContent = 'Gagal memuat info stok.';
            });
    }

    // --- Update Stock Info Display ---
    function updateStockInfo() {
        if (!stockInfo || !itemIdInput) return;
        const selectedItemId = itemIdInput.value.trim().toUpperCase();
        const item = currentInventory[selectedItemId];
        if (item) {
            stockInfo.textContent = `Stok saat ini: ${formatNumber(item.quantity)}`;
             stockInfo.className = 'form-text text-muted'; // Reset color
        } else {
            stockInfo.textContent = 'Pilih item ID yang valid untuk melihat stok.';
             stockInfo.className = 'form-text text-warning';
        }
    }

    // --- Load Recent Outgoing Transactions ---
    function loadRecentOutgoing() {
        if (!recentOutgoingContainer) return;
        recentOutgoingContainer.innerHTML = createSpinner('Memuat riwayat...', true);

        fetch('/api/transactions?type=keluar') // Filter by type=keluar
             .then(response => {
                 if (!response.ok) return response.json().then(err => Promise.reject(err.error || `HTTP error! status: ${response.status}`));
                 return response.json();
             })
             .then(transactions => {
                 displayTransactionsTable(transactions);
             })
             .catch(error => {
                 console.error('Error loading outgoing transactions:', error);
                 recentOutgoingContainer.innerHTML = createAlert(`Gagal memuat riwayat: ${error}`, 'danger');
             });
    }

    // --- Display Transactions Table ---
    function displayTransactionsTable(transactions) {
        if (!transactions || transactions.length === 0) {
            recentOutgoingContainer.innerHTML = createAlert('Belum ada transaksi barang keluar.', 'info');
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
                    <td class="text-end text-danger">-${formatNumber(tx.quantity)}</td>
                    <td>${tx.user || '-'}</td>
                    <td><small>${tx.timestamp || '-'}</small></td>
                     <td><small>${tx.notes || '-'}</small></td>
                </tr>`;
        });
        tableHTML += `</tbody></table>`;
         recentOutgoingContainer.innerHTML = tableHTML;
    }

    // --- Handle Outgoing Form Submission ---
    if (outgoingForm) {
        outgoingForm.addEventListener('submit', function(event) {
            event.preventDefault();
            clearFeedback(outgoingFeedback);
            outgoingFeedback.innerHTML = createSpinner('Menyimpan...', true);

             const formData = new FormData(outgoingForm);
             const data = Object.fromEntries(formData.entries());
             const itemId = data.item_id.trim().toUpperCase();
             const quantity = parseInt(data.quantity);

             // Client-side validation
             if (!itemId || !currentInventory[itemId]) {
                 showFeedback(outgoingFeedback, 'Pilih Item ID yang valid.', 'warning');
                 return;
             }
              if (isNaN(quantity) || quantity <= 0) {
                 showFeedback(outgoingFeedback, 'Jumlah harus berupa angka positif.', 'warning');
                 return;
             }
              if (currentInventory[itemId].quantity < quantity) {
                 showFeedback(outgoingFeedback, `Stok tidak mencukupi! Stok ${itemId}: ${currentInventory[itemId].quantity}.`, 'danger');
                 return;
             }

            // Add item_id back in correct case if needed by API
            data.item_id = itemId; 

            fetch('/api/transactions/outgoing', {
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
                 showFeedback(outgoingFeedback, `Barang keluar (ID: ${newTransaction.id}) untuk item <code>${newTransaction.item_id}</code> sejumlah ${newTransaction.quantity} berhasil dicatat!`, 'success');
                 outgoingForm.reset();
                 // Reload inventory (to update stock count) and recent transactions
                 loadInventoryItems(); 
                 loadRecentOutgoing();
                 // Update stock info display immediately after reset
                 updateStockInfo(); 
            })
            .catch(error => {
                console.error('Error recording outgoing transaction:', error);
                 showFeedback(outgoingFeedback, `Gagal mencatat barang keluar: ${error}`, 'danger');
            });
        });
    }

    // --- Event Listener for Item ID Change ---
    if (itemIdInput) {
        // Use 'input' event to catch changes from typing or datalist selection
        itemIdInput.addEventListener('input', updateStockInfo);
    }


    // --- Initial Loads ---
    loadInventoryItems();
    loadRecentOutgoing();

});