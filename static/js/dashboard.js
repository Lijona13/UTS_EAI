// static/js/dashboard.js
document.addEventListener('DOMContentLoaded', function() {
    const summaryContainer = document.getElementById('dashboard-summary');
    const transactionsTableContainer = document.getElementById('recent-transactions-table'); // Ganti ID jika berbeda

    // Fungsi format Angka (opsional)
    function formatNumber(num) {
        return new Intl.NumberFormat('id-ID').format(num);
    }

    // Fungsi untuk mengambil data summary dari API
    function fetchSummaryData() {
         // Pastikan container ada sebelum fetch
        if (!summaryContainer || !transactionsTableContainer) {
            console.warn("Dashboard summary/transaction elements not found.");
            return; 
        }
        
        // Tampilkan spinner awal
        summaryContainer.innerHTML = createSpinner('Memuat data summary...');
        transactionsTableContainer.innerHTML = createSpinner('Memuat transaksi terkini...');

        fetch('/api/dashboard/summary') // Panggil API endpoint
            .then(response => {
                if (!response.ok) {
                    if (response.status === 403) {
                         throw new Error('Akses ditolak (403)');
                    }
                     // Coba parse error dari JSON body jika ada
                     return response.json().then(err => { throw new Error(err.error || `HTTP error! status: ${response.status}`) });
                }
                return response.json(); // Parse JSON response
            })
            .then(data => {
                // Tampilkan data summary di HTML
                displaySummaryCards(data);
                // Tampilkan transaksi terkini
                displayRecentTransactionsTable(data.recent_transactions);
            })
            .catch(error => {
                console.error('Error fetching dashboard data:', error);
                summaryContainer.innerHTML = createAlert(`Gagal memuat data summary: ${error.message}`, 'danger');
                transactionsTableContainer.innerHTML = createAlert(`Gagal memuat transaksi terkini.`, 'danger'); 
            });
    }
    
    // Fungsi membuat elemen spinner Bootstrap
    function createSpinner(message = 'Loading...') {
        return `
            <div class="d-flex justify-content-center align-items-center text-secondary mt-3">
                <div class="spinner-border spinner-border-sm" role="status">
                    <span class="visually-hidden">${message}</span>
                </div>
                <span class="ms-2">${message}</span>
            </div>`;
    }

    // Fungsi membuat elemen alert Bootstrap
    function createAlert(message, type = 'info') {
        return `<div class="alert alert-${type}" role="alert">${message}</div>`;
    }

    // Fungsi untuk menampilkan cards summary
    function displaySummaryCards(data) {
        if (!data) {
            summaryContainer.innerHTML = createAlert('Data summary tidak tersedia.', 'warning');
            return;
        }
         summaryContainer.innerHTML = `
            <div class="col-md-4 mb-3">
                <div class="card text-white bg-primary shadow-sm">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                             <div>
                                <h5 class="card-title mb-0">${formatNumber(data.total_unique_items || 0)}</h5>
                                <p class="card-text small mb-0">Item Unik</p>
                            </div>
                             <i class="bi bi-boxes fs-1 opacity-50"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-3">
                <div class="card text-white bg-success shadow-sm">
                     <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                             <div>
                                <h5 class="card-title mb-0">${formatNumber(data.total_stock_quantity || 0)}</h5>
                                <p class="card-text small mb-0">Total Stok</p>
                            </div>
                             <i class="bi bi-check-all fs-1 opacity-50"></i>
                        </div>
                    </div>
                </div>
            </div>
             <div class="col-md-4 mb-3">
                <div class="card text-dark bg-warning shadow-sm">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center">
                             <div>
                                <h5 class="card-title mb-0">${formatNumber(data.recent_transactions_count || 0)}</h5>
                                <p class="card-text small mb-0">Total Transaksi</p>
                            </div>
                             <i class="bi bi-receipt-cutoff fs-1 opacity-50"></i>
                        </div>
                    </div>
                </div>
            </div>
            `;
    }

    // Fungsi untuk menampilkan tabel transaksi terkini
    function displayRecentTransactionsTable(transactions) {
        if (!transactions || transactions.length === 0) {
            transactionsTableContainer.innerHTML = createAlert('Belum ada transaksi tercatat.', 'info');
            return;
        }

        let tableHTML = `
            <table class="table table-striped table-hover table-sm">
                <thead class="table-light">
                    <tr>
                        <th>ID</th>
                        <th>Tipe</th>
                        <th>Item ID</th>
                        <th>Jumlah</th>
                         <th>Oleh</th>
                        <th>Waktu</th>
                        <th>Catatan</th>
                    </tr>
                </thead>
                <tbody>
        `;

        transactions.forEach(tx => {
            const typeClass = tx.type === 'masuk' ? 'success' : 'danger';
            const typeIcon = tx.type === 'masuk' ? 'plus-circle-fill' : 'dash-circle-fill';
            tableHTML += `
                <tr>
                    <td>${tx.id}</td>
                    <td><span class="badge bg-${typeClass}"><i class="bi bi-${typeIcon} me-1"></i> ${tx.type}</span></td>
                    <td><code>${tx.item_id}</code></td>
                    <td>${formatNumber(tx.quantity)}</td>
                    <td>${tx.user || '-'}</td>
                    <td><small>${tx.timestamp || '-'}</small></td>
                     <td><small>${tx.notes || '-'}</small></td>
                </tr>
            `;
        });

        tableHTML += `
                </tbody>
            </table>
             <div class="text-end">
                <a href="#" class="btn btn-sm btn-outline-secondary disabled">Lihat Semua Transaksi (TODO)</a>
            </div>
        `;
        transactionsTableContainer.innerHTML = tableHTML;
    }

    // Panggil fungsi untuk fetch data saat halaman dimuat
    fetchSummaryData();

});