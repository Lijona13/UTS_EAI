import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
# Ganti dengan secret key yang kuat, bisa dari environment variable
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'ganti-dengan-kunci-rahasia-yang-kuat-dan-unik')

# --- Konfigurasi Database MySQL ---
db_user = os.environ.get('MYSQL_USER', 'root') # Default 'root'
db_password = os.environ.get('MYSQL_PASSWORD') # WAJIB diatur di environment
# !!! DEBUGGING: Cetak nilai db_password yang dibaca !!!
print(f"DEBUG: MYSQL_PASSWORD dibaca sebagai: '{db_password}'") 
# !!! END DEBUGGING !!!
db_host = os.environ.get('MYSQL_HOST', 'localhost') # Default 'localhost'
db_name = os.environ.get('MYSQL_DATABASE', 'inventory_db') # Default 'inventory_db'

# Ubah pengecekan: Hanya error jika variabel TIDAK ADA (None), izinkan string kosong ''
if db_password is None:
    raise ValueError("Environment variable MYSQL_PASSWORD tidak diatur! Pastikan ada di file .env atau environment sistem.")

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{db_user}:{db_password}@{db_host}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
# --- End Konfigurasi Database ---

# Tambahkan context processor untuk menyediakan fungsi now() ke semua template
@app.context_processor
def utility_processor():
    return dict(now=datetime.now)

# --- Model Database SQLAlchemy ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False) # Simpan hash, bukan password asli
    role = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    transactions = db.relationship('Transaction', backref='user_obj', lazy=True) # Relasi ke Transaction

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class InventoryItem(db.Model):
    id = db.Column(db.String(50), primary_key=True) # Misal ITEM001
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    category = db.Column(db.String(50))
    added_by = db.Column(db.String(80)) # Bisa jadi foreign key ke User.username jika diinginkan
    last_update = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    transactions = db.relationship('Transaction', backref='item', lazy=True) # Relasi ke Transaction

    def __repr__(self):
        return f'<InventoryItem {self.id} - {self.name}>'

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10), nullable=False) # 'masuk' atau 'keluar'
    item_id = db.Column(db.String(50), db.ForeignKey('inventory_item.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    user_username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False) # Foreign key ke username
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

    def __repr__(self):
        return f'<Transaction {self.id} - {self.type} - {self.item_id}>'

# --- End Model Database ---

# --- Helper Function ---
def get_current_timestamp():
    """Mendapatkan timestamp string format Tahun-Bulan-Tanggal Jam:Menit:Detik (dipertahankan jika masih diperlukan, tapi model Transaction pakai datetime object)"""
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# --- Decorators untuk Otentikasi & Otorisasi ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Akses ditolak. Silakan login terlebih dahulu.', 'warning')
            return redirect(url_for('login'))
        # Periksa juga apakah user di session masih ada di DB (opsional tapi lebih aman)
        user_in_db = User.query.filter_by(username=session['user']['username']).first()
        if not user_in_db:
            session.pop('user', None)
            flash('Sesi tidak valid, silakan login kembali.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    """Decorator untuk membatasi akses berdasarkan role."""
    def role_decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                flash('Akses ditolak. Silakan login terlebih dahulu.', 'warning')
                return redirect(url_for('login'))

            user_role = session['user'].get('role')
            if user_role not in allowed_roles:
                flash(f'Akses ditolak. Role "{user_role}" tidak diizinkan mengakses halaman ini.', 'danger')
                return redirect(url_for('unauthorized'))
            return f(*args, **kwargs)
        return decorated_function
    return role_decorator

# --- Routes untuk Halaman Web (View Rendering) ---

@app.route('/')
def home():
    """Halaman utama, redirect ke login jika belum login, atau dashboard jika sudah."""
    if 'user' in session:
        return redirect(url_for('dashboard_view'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Halaman Login - Menggunakan Database"""
    if 'user' in session:
        return redirect(url_for('dashboard_view'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username dan password harus diisi.', 'warning')
            return render_template('login.html')

        # Cari user di database
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Simpan informasi user ke session
            session['user'] = {
                'username': user.username,
                'role': user.role,
                'name': user.name
            }
            flash(f"Login berhasil! Selamat datang, {user.name}.", 'success')
            return redirect(url_for('dashboard_view'))
        else:
            flash('Username atau password salah.', 'danger')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Halaman Registrasi untuk user baru - Menggunakan Database"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        name = request.form.get('name')
        # Role diatur default sebagai 'operator'
        role = 'operator'

        if not all([username, password, name]):
            flash('Semua field (username, password, nama) harus diisi.', 'warning')
        elif User.query.filter_by(username=username).first():
            flash(f'Username "{username}" sudah digunakan.', 'warning')
        else:
            try:
                # Buat user baru dan hash passwordnya
                new_user = User(username=username, role=role, name=name)
                new_user.set_password(password) # Password di-hash di sini

                db.session.add(new_user)
                db.session.commit()

                flash(f'Registrasi berhasil untuk {username}! Anda terdaftar sebagai {role}. Silakan login.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback() # Batalkan jika ada error
                flash(f'Terjadi kesalahan saat registrasi: {e}', 'danger')
                app.logger.error(f"Error during registration for {username}: {e}")


    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    user_name = session.get('user', {}).get('name', 'User')
    session.pop('user', None)
    flash(f'Anda ({user_name}) telah berhasil logout.', 'info')
    return redirect(url_for('login'))

@app.route('/unauthorized')
@login_required
def unauthorized():
    """Halaman pemberitahuan akses tidak diizinkan."""
    return render_template('unauthorized.html'), 403


# --- View Routes (Render Template) ---
# (View routes yang lain tetap sama, logika data dipindahkan ke API routes)

@app.route('/dashboard')
@login_required
def dashboard_view():
    user_role = session.get('user', {}).get('role')
    return render_template('dashboard.html', user_role=user_role)

@app.route('/inventory')
@login_required
@role_required(['admin', 'manajer', 'operator'])
def inventory_view():
    user_role = session.get('user', {}).get('role')
    return render_template('inventory.html', user_role=user_role)

@app.route('/input-barang')
@login_required
@role_required(['admin', 'operator'])
def barang_masuk_view():
    user_role = session.get('user', {}).get('role')
    return render_template('barang_masuk.html', user_role=user_role)

@app.route('/barang-keluar')
@login_required
@role_required(['admin', 'operator'])
def barang_keluar_view():
    user_role = session.get('user', {}).get('role')
    return render_template('barang_keluar.html', user_role=user_role)

@app.route('/manage-users')
@login_required
@role_required(['admin'])
def manage_users_view():
    user_role = session.get('user', {}).get('role')
    # Data user akan diambil via API, jadi tidak perlu dikirim dari sini
    return render_template('manajemen_akun.html', user_role=user_role)


# --- API Routes (Logika Bisnis & Interaksi Database) ---
# TODO: Ganti semua logika API untuk menggunakan SQLAlchemy

@app.route('/api/dashboard/summary', methods=['GET'])
@login_required
@role_required(['admin', 'manajer']) # Hanya admin & manajer boleh lihat summary
def api_dashboard_summary():
    """API Endpoint untuk mendapatkan data summary dashboard."""
    try:
        # Hitung jumlah item unik
        total_unique_items = InventoryItem.query.count()

        # Hitung total kuantitas stok
        total_stock_quantity = db.session.query(db.func.sum(InventoryItem.quantity)).scalar() or 0

        # Hitung total transaksi
        total_transactions = Transaction.query.count()

        # Ambil 5 transaksi terbaru (Kembalikan order by timestamp)
        recent_transactions = Transaction.query.order_by(Transaction.timestamp.desc()).limit(5).all()
        # recent_transactions = Transaction.query.order_by(Transaction.id.desc()).limit(5).all() # Order by ID for DEBUGGING

        # Format data transaksi terkini
        recent_activity_list = []
        for t in recent_transactions:
            # Coba dapatkan nama item, tangani jika item mungkin sudah dihapus (meskipun FK constraint harusnya mencegah)
            item_name = t.item.name if t.item else "[Item Dihapus]"
            recent_activity_list.append({
                'id': t.id,
                'type': t.type,
                'item_id': t.item_id,
                'item_name': item_name,
                'quantity': t.quantity,
                'user': t.user_username,
                'timestamp': t.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'notes': t.notes
            })

        summary_data = {
            'total_unique_items': total_unique_items,
            'total_stock_quantity': total_stock_quantity,
            'total_transactions': total_transactions,
            # 'low_stock_items': 0, # TODO: Implementasi jika diperlukan
            'recent_activity': recent_activity_list
        }
        return jsonify(summary_data)

    except Exception as e:
        app.logger.error(f"Error fetching dashboard summary: {e}")
        return jsonify({"error": "Gagal mengambil ringkasan dashboard"}), 500


@app.route('/api/inventory', methods=['GET'])
@login_required
@role_required(['admin', 'manajer', 'operator'])
def api_get_inventory():
    # TODO: Implementasi dengan query SQLAlchemy
    try:
        items = InventoryItem.query.all()
        inventory_list = [
            {
                'id': item.id,
                'name': item.name,
                'quantity': item.quantity,
                'category': item.category,
                'added_by': item.added_by,
                'last_update': item.last_update.strftime('%Y-%m-%d %H:%M:%S') if item.last_update else None
            } for item in items
        ]
        return jsonify(inventory_list)
    except Exception as e:
        app.logger.error(f"Error fetching inventory: {e}")
        return jsonify({"error": "Gagal mengambil data inventaris"}), 500

@app.route('/api/inventory', methods=['POST'])
@login_required
@role_required(['admin', 'operator'])
def api_add_inventory_item():
    """API Endpoint untuk menambahkan item inventaris baru."""
    if not request.is_json:
        return jsonify({"error": "Request harus dalam format JSON"}), 400

    data = request.get_json()
    item_id = data.get('item_id')
    name = data.get('name')
    category = data.get('category')
    quantity_str = data.get('quantity') # Ambil sebagai string

    # Validasi input dasar
    if not all([item_id, name, category, quantity_str]):
        return jsonify({"error": "ID Item, Nama, Kategori, dan Jumlah Awal harus diisi"}), 400

    # Validasi ID Item (misal: tidak boleh kosong setelah strip)
    item_id = item_id.strip().upper()
    if not item_id:
         return jsonify({"error": "ID Item tidak boleh kosong"}), 400

    # Validasi jumlah
    try:
        quantity = int(quantity_str)
        if quantity < 0:
            return jsonify({"error": "Jumlah Awal tidak boleh negatif"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Jumlah Awal harus berupa angka bulat non-negatif"}), 400

    # Cek apakah ID sudah ada
    if InventoryItem.query.get(item_id):
        return jsonify({"error": f"Item dengan ID {item_id} sudah ada"}), 409 # Conflict

    try:
        current_user = session.get('user', {}).get('username')
        if not current_user:
            return jsonify({"error": "Sesi pengguna tidak valid"}), 401

        # Buat item baru
        new_item = InventoryItem(
            id=item_id,
            name=name.strip(),
            quantity=quantity,
            category=category.strip(),
            added_by=current_user
            # last_update akan diatur otomatis oleh default/onupdate
        )

        db.session.add(new_item)
        db.session.commit()

        # Return data item yang baru dibuat
        item_data = {
            'id': new_item.id,
            'name': new_item.name,
            'quantity': new_item.quantity,
            'category': new_item.category,
            'added_by': new_item.added_by,
            'last_update': new_item.last_update.strftime('%Y-%m-%d %H:%M:%S') if new_item.last_update else None
        }
        return jsonify(item_data), 201 # Created

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding inventory item {item_id}: {e}")
        return jsonify({"error": "Gagal menambahkan item ke database"}), 500

@app.route('/api/inventory/<item_id>', methods=['GET'])
@login_required
@role_required(['admin', 'manajer', 'operator']) # Semua boleh lihat detail
def api_get_inventory_item(item_id):
    """API Endpoint untuk mendapatkan detail item inventaris."""
    try:
        item = InventoryItem.query.get(item_id)
        if not item:
            return jsonify({"error": f"Item dengan ID {item_id} tidak ditemukan"}), 404

        item_data = {
            'id': item.id,
            'name': item.name,
            'quantity': item.quantity,
            'category': item.category,
            'added_by': item.added_by,
            'last_update': item.last_update.strftime('%Y-%m-%d %H:%M:%S') if item.last_update else None
        }
        return jsonify(item_data)
    except Exception as e:
        app.logger.error(f"Error fetching item {item_id}: {e}")
        return jsonify({"error": "Gagal mengambil detail item"}), 500

@app.route('/api/inventory/<item_id>', methods=['PUT'])
@login_required
@role_required(['admin']) # Hanya admin boleh update
def api_update_inventory_item(item_id):
    """API Endpoint untuk mengupdate item inventaris (hanya Admin)."""
    if not request.is_json:
        return jsonify({"error": "Request harus dalam format JSON"}), 400

    item = InventoryItem.query.get(item_id)
    if not item:
        return jsonify({"error": f"Item dengan ID {item_id} tidak ditemukan"}), 404

    data = request.get_json()
    updated = False

    try:
        if 'name' in data:
            name = data['name'].strip()
            if not name:
                return jsonify({"error": "Nama item tidak boleh kosong"}), 400
            if item.name != name:
                item.name = name
                updated = True

        if 'category' in data:
            category = data['category'].strip()
            if not category:
                 return jsonify({"error": "Kategori tidak boleh kosong"}), 400
            if item.category != category:
                item.category = category
                updated = True

        # Note: Mengubah quantity sebaiknya melalui transaksi masuk/keluar
        # Jika ingin mengizinkan penyesuaian langsung (misal stock opname):
        if 'quantity' in data:
             try:
                 quantity = int(data['quantity'])
                 if quantity < 0:
                     return jsonify({"error": "Jumlah tidak boleh negatif"}), 400
                 if item.quantity != quantity:
                     item.quantity = quantity
                     updated = True # Anggap perlu update timestamp jika quantity berubah
             except (ValueError, TypeError):
                 return jsonify({"error": "Jumlah harus berupa angka bulat"}), 400

        if updated:
            # Timestamp last_update akan otomatis diupdate oleh onupdate=datetime.utcnow
            db.session.commit()

        # Return item yang sudah diupdate
        item_data = {
            'id': item.id,
            'name': item.name,
            'quantity': item.quantity,
            'category': item.category,
            'added_by': item.added_by,
            'last_update': item.last_update.strftime('%Y-%m-%d %H:%M:%S') if item.last_update else None
        }
        return jsonify(item_data)

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating item {item_id}: {e}")
        return jsonify({"error": "Gagal mengupdate item"}), 500

@app.route('/api/inventory/<item_id>', methods=['DELETE'])
@login_required
@role_required(['admin']) # Hanya admin boleh delete
def api_delete_inventory_item(item_id):
    """API Endpoint untuk menghapus item inventaris (hanya Admin)."""
    item = InventoryItem.query.get(item_id)
    if not item:
        return jsonify({"error": f"Item dengan ID {item_id} tidak ditemukan"}), 404

    try:
        # Cek apakah ada transaksi terkait item ini
        transaction_count = Transaction.query.filter_by(item_id=item_id).count()
        if transaction_count > 0:
            return jsonify({"error": f"Tidak dapat menghapus item '{item.name}' karena memiliki {transaction_count} riwayat transaksi."}), 400

        # Opsional: Cek apakah stok masih ada (mungkin tidak perlu jika cek transaksi sudah cukup)
        # if item.quantity > 0:
        #     return jsonify({"error": f"Tidak dapat menghapus item '{item.name}' karena stok masih ada ({item.quantity})."}), 400

        # Hapus item
        item_name = item.name # Simpan nama untuk pesan respons
        db.session.delete(item)
        db.session.commit()

        return jsonify({"message": f"Item '{item_name}' (ID: {item_id}) berhasil dihapus"})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting item {item_id}: {e}")
        return jsonify({"error": "Gagal menghapus item"}), 500

# --- API Users ---
@app.route('/api/users', methods=['GET'])
@login_required
@role_required(['admin'])
def api_get_users():
    """API Endpoint untuk mendapatkan daftar pengguna (hanya Admin)."""
    try:
        users = User.query.all()
        users_list = [
            {
                'username': user.username,
                'name': user.name,
                'role': user.role
                # Jangan sertakan password_hash!
            } for user in users
        ]
        return jsonify(users_list)
    except Exception as e:
        app.logger.error(f"Error fetching users: {e}")
        return jsonify({"error": "Gagal mengambil data pengguna"}), 500

@app.route('/api/users', methods=['POST'])
@login_required
@role_required(['admin'])
def api_add_user():
    """API Endpoint untuk menambah pengguna baru (hanya Admin)."""
    if not request.is_json:
        return jsonify({"error": "Request harus dalam format JSON"}), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')
    role = data.get('role')

    # Validasi input dasar
    if not all([username, password, name, role]):
        return jsonify({"error": "Semua field (username, password, nama, role) harus diisi"}), 400

    # Validasi role
    allowed_roles = ['admin', 'manajer', 'operator']
    if role not in allowed_roles:
        return jsonify({"error": f"Role tidak valid. Pilih salah satu dari: {', '.join(allowed_roles)}"}), 400

    # Cek apakah username sudah ada
    if User.query.filter_by(username=username).first():
        return jsonify({"error": f"Username '{username}' sudah digunakan"}), 409 # 409 Conflict

    try:
        # Buat user baru
        new_user = User(username=username, name=name, role=role)
        new_user.set_password(password) # Hash password

        db.session.add(new_user)
        db.session.commit()

        # Return data user baru (tanpa password hash)
        user_data = {
            'username': new_user.username,
            'name': new_user.name,
            'role': new_user.role
        }
        return jsonify(user_data), 201 # 201 Created

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding user {username}: {e}")
        return jsonify({"error": "Gagal menambahkan pengguna ke database"}), 500

@app.route('/api/users/<username>', methods=['PUT'])
@login_required
@role_required(['admin'])
def api_update_user(username):
    """API Endpoint untuk mengupdate data pengguna (hanya Admin)."""
    if not request.is_json:
        return jsonify({"error": "Request harus dalam format JSON"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": f"Pengguna '{username}' tidak ditemukan"}), 404

    data = request.get_json()
    updated = False

    try:
        if 'name' in data:
            name = data['name'].strip()
            if not name:
                return jsonify({"error": "Nama tidak boleh kosong"}), 400
            if user.name != name:
                user.name = name
                updated = True

        if 'role' in data:
            role = data['role']
            allowed_roles = ['admin', 'manajer', 'operator']
            if role not in allowed_roles:
                return jsonify({"error": f"Role tidak valid. Pilih salah satu dari: {', '.join(allowed_roles)}"}), 400
            # Cegah admin mengubah role dirinya sendiri (jika diinginkan, bisa dihapus)
            if username == session.get('user', {}).get('username') and user.role == 'admin' and role != 'admin':
                 return jsonify({"error": "Admin tidak dapat mengubah role dirinya sendiri."}), 400
            if user.role != role:
                user.role = role
                updated = True

        # Update password jika diberikan dan tidak kosong
        if 'password' in data and data['password']:
            user.set_password(data['password']) # Password akan di-hash
            updated = True

        if updated:
            db.session.commit()

        # Return data user yang diupdate (tanpa password hash)
        user_data = {
            'username': user.username,
            'name': user.name,
            'role': user.role
        }
        return jsonify(user_data)

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating user {username}: {e}")
        return jsonify({"error": "Gagal mengupdate pengguna"}), 500

@app.route('/api/users/<username>', methods=['DELETE'])
@login_required
@role_required(['admin'])
def api_delete_user(username):
    """API Endpoint untuk menghapus pengguna (hanya Admin)."""
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": f"Pengguna '{username}' tidak ditemukan"}), 404

    # Cek apakah user mencoba menghapus dirinya sendiri
    if username == session.get('user', {}).get('username'):
        return jsonify({"error": "Tidak dapat menghapus akun Anda sendiri."}), 400

    try:
        # Cek apakah user punya transaksi (opsional, tergantung aturan bisnis)
        # transaction_count = Transaction.query.filter_by(user_username=username).count()
        # if transaction_count > 0:
        #     return jsonify({"error": f"Tidak dapat menghapus pengguna '{username}' karena memiliki riwayat transaksi."}), 400

        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Pengguna '{username}' berhasil dihapus"})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting user {username}: {e}")
        # Tangani error jika ada foreign key constraint (misal dari transaksi)
        if "foreign key constraint" in str(e).lower():
             return jsonify({"error": f"Tidak dapat menghapus pengguna '{username}' karena terkait dengan data lain (misal: transaksi)."}), 400
        return jsonify({"error": "Gagal menghapus pengguna"}), 500

# --- API Transactions ---
@app.route('/api/transactions', methods=['GET'])
@login_required
# Akses role bisa disesuaikan, mungkin semua perlu lihat transaksi?
@role_required(['admin', 'manajer', 'operator'])
def api_get_transactions():
    """API Endpoint untuk mendapatkan daftar transaksi, bisa difilter by type."""
    try:
        query = Transaction.query

        # Filter berdasarkan tipe jika ada di query args
        transaction_type = request.args.get('type')
        if transaction_type in ['masuk', 'keluar']:
            query = query.filter_by(type=transaction_type)

        # Urutkan berdasarkan timestamp terbaru
        transactions = query.order_by(Transaction.timestamp.desc()).all()

        transactions_list = []
        for t in transactions:
            transactions_list.append({
                'id': t.id,
                'type': t.type,
                'item_id': t.item_id,
                'item_name': t.item.name, # Ambil nama item dari relasi
                'quantity': t.quantity,
                'user': t.user_username,
                'timestamp': t.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'notes': t.notes
            })

        return jsonify(transactions_list)

    except Exception as e:
        app.logger.error(f"Error fetching transactions: {e}")
        return jsonify({"error": "Gagal mengambil data transaksi"}), 500

@app.route('/api/transactions/incoming', methods=['POST'])
@login_required
@role_required(['admin', 'operator'])
def api_add_incoming_transaction():
    """API Endpoint untuk menambah transaksi barang masuk."""
    if not request.is_json:
        return jsonify({"error": "Request harus dalam format JSON"}), 400

    data = request.get_json()
    item_id = data.get('item_id')
    quantity_str = data.get('quantity') # Ambil sebagai string dulu
    notes = data.get('notes', '')

    # Validasi input
    if not item_id or not quantity_str:
        return jsonify({"error": "ID Item dan Jumlah Masuk harus diisi"}), 400

    try:
        quantity = int(quantity_str)
        if quantity <= 0:
            return jsonify({"error": "Jumlah Masuk harus lebih dari 0"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Jumlah Masuk harus berupa angka bulat positif"}), 400

    try:
        # Cari item inventaris
        item = InventoryItem.query.get(item_id)
        if not item:
            return jsonify({"error": f"Item dengan ID {item_id} tidak ditemukan"}), 404

        # Dapatkan username dari session
        current_user = session.get('user', {}).get('username')
        if not current_user:
            return jsonify({"error": "Sesi pengguna tidak valid"}), 401

        # Buat transaksi baru dan update stok dalam satu sesi DB
        new_transaction = Transaction(
            type='masuk',
            item_id=item_id,
            quantity=quantity,
            user_username=current_user,
            timestamp=datetime.utcnow(),
            notes=notes
        )

        # Update kuantitas item
        item.quantity += quantity

        db.session.add(new_transaction)
        # item sudah di-track oleh session karena kita load & modifikasi
        db.session.commit()

        # Return data transaksi yang baru dibuat
        transaction_data = {
            'id': new_transaction.id,
            'type': new_transaction.type,
            'item_id': new_transaction.item_id,
            'item_name': item.name, # Sertakan nama item
            'quantity': new_transaction.quantity,
            'user': new_transaction.user_username,
            'timestamp': new_transaction.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'notes': new_transaction.notes
        }
        return jsonify(transaction_data), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding incoming transaction for item {item_id}: {e}")
        return jsonify({"error": "Gagal mencatat transaksi barang masuk"}), 500

@app.route('/api/transactions/outgoing', methods=['POST'])
@login_required
@role_required(['admin', 'operator'])
def api_add_outgoing_transaction():
    """API Endpoint untuk menambah transaksi barang keluar."""
    if not request.is_json:
        return jsonify({"error": "Request harus dalam format JSON"}), 400

    data = request.get_json()
    item_id = data.get('item_id')
    quantity_str = data.get('quantity')
    notes = data.get('notes', '')

    # Validasi input
    if not item_id or not quantity_str:
        return jsonify({"error": "ID Item dan Jumlah Keluar harus diisi"}), 400

    try:
        quantity = int(quantity_str)
        if quantity <= 0:
            return jsonify({"error": "Jumlah Keluar harus lebih dari 0"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Jumlah Keluar harus berupa angka bulat positif"}), 400

    try:
        # Cari item inventaris
        item = InventoryItem.query.get(item_id)
        if not item:
            return jsonify({"error": f"Item dengan ID {item_id} tidak ditemukan"}), 404

        # Cek stok mencukupi
        if item.quantity < quantity:
            return jsonify({"error": f"Stok tidak mencukupi. Stok saat ini: {item.quantity}"}), 400

        # Dapatkan username dari session
        current_user = session.get('user', {}).get('username')
        if not current_user:
            return jsonify({"error": "Sesi pengguna tidak valid"}), 401

        # Buat transaksi baru dan update stok dalam satu sesi DB
        new_transaction = Transaction(
            type='keluar',
            item_id=item_id,
            quantity=quantity,
            user_username=current_user,
            timestamp=datetime.utcnow(),
            notes=notes
        )

        # Update kuantitas item
        item.quantity -= quantity

        db.session.add(new_transaction)
        db.session.commit()

        # Return data transaksi yang baru dibuat
        transaction_data = {
            'id': new_transaction.id,
            'type': new_transaction.type,
            'item_id': new_transaction.item_id,
            'item_name': item.name,
            'quantity': new_transaction.quantity,
            'user': new_transaction.user_username,
            'timestamp': new_transaction.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'notes': new_transaction.notes
        }
        return jsonify(transaction_data), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding outgoing transaction for item {item_id}: {e}")
        return jsonify({"error": "Gagal mencatat transaksi barang keluar"}), 500

# --- Fungsi Inisialisasi Database ---
def init_db():
    """Membuat tabel database jika belum ada."""
    with app.app_context():
        print("Mencoba membuat tabel database...")
        try:
            db.create_all()
            print("Tabel berhasil dibuat (atau sudah ada).")

            # Opsional: Tambah user admin default jika tabel baru dibuat & user admin belum ada
            if not User.query.filter_by(username='admin').first():
                print("Membuat user admin default...")
                admin_user = User(username='admin', role='admin', name='Admin Utama')
                admin_pass = os.environ.get('ADMIN_DEFAULT_PASSWORD', 'adminpass')
                if not admin_pass:
                    print("PERINGATAN: ADMIN_DEFAULT_PASSWORD tidak diatur, menggunakan 'adminpass' default yang lemah.")
                    admin_pass = 'adminpass'
                admin_user.set_password(admin_pass)
                db.session.add(admin_user)
                db.session.commit()
                print("User admin default berhasil dibuat.")
        except Exception as e:
            print(f"Error saat membuat tabel atau user admin: {e}")
            db.session.rollback()

# --- Command Flask CLI untuk init-db ---
@app.cli.command("init-db")
def initialize_database():
    """Membuat tabel database."""
    init_db()

# --- Run Flask App (Hanya untuk menjalankan langsung dengan python app.py) ---
if __name__ == '__main__':
    # Perintah init-db sudah dipindah keluar dari sini
    app.run(debug=True) # debug=True hanya untuk pengembangan


# --- Perlu dilanjutkan ---
# - Implementasi sisa API endpoints (/api/inventory POST/PUT/DELETE, /api/transactions GET/POST, /api/users GET/POST/PUT/DELETE) menggunakan SQLAlchemy.
# - Pastikan frontend (JavaScript) masih kompatibel dengan struktur data JSON dari API baru.
# - Tambahkan penanganan error yang lebih baik.
# - Setup environment variables untuk konfigurasi.
# - Jalankan `flask init-db` sekali di terminal setelah mengatur environment variables.