# utils/auth.py
from functools import wraps
from flask import session, flash, redirect, url_for

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Akses ditolak. Silakan login terlebih dahulu.', 'warning')
            return redirect(url_for('login', next=request.url)) # 'login' adalah nama fungsi view login
        return f(*args, **kwargs)
    return decorated_function

def role_required(allowed_roles):
    """Decorator untuk membatasi akses berdasarkan role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session: # Harus login dulu
                flash('Akses ditolak. Silakan login terlebih dahulu.', 'warning')
                return redirect(url_for('login', next=request.url))
            
            user_role = session['user'].get('role')
            if user_role not in allowed_roles:
                flash(f'Akses ditolak. Role "{user_role}" tidak diizinkan mengakses halaman ini.', 'danger')
                 # 'unauthorized' adalah nama fungsi view unauthorized
                return redirect(url_for('unauthorized')) 
            return f(*args, **kwargs)
        return decorator
    return decorator

# Kemudian di app.py: from utils.auth import login_required, role_required