
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///employees.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    permissions = db.Column(db.JSON)
    is_protected = db.Column(db.Boolean, default=False)  # Protected roles can't be deleted/modified
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    users = db.relationship('User', backref='role_obj', lazy=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False, default=3)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def has_permission(self, permission):
        if not self.role_obj:
            return False
        return permission in (self.role_obj.permissions or [])
    
    @property
    def role_name(self):
        return self.role_obj.name if self.role_obj else 'Unknown'
    
    @property
    def is_super_admin(self):
        return self.role_name == 'Super Admin'

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    department = db.Column(db.String(50), nullable=False)
    position = db.Column(db.String(50), nullable=False)
    salary = db.Column(db.Float)
    hire_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), default='Active')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user_account = db.relationship('User', foreign_keys=[user_id], backref='employee_profile')
    creator = db.relationship('User', foreign_keys=[created_by])

# Enhanced permission decorators
def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Silakan login terlebih dahulu!', 'error')
                return redirect(url_for('login'))
            
            user = User.query.get(session['user_id'])
            if user is None:
                flash('Pengguna tidak ditemukan!', 'error')
                return redirect(url_for('login'))
            
            if not user.has_permission(permission):
                flash('Anda tidak memiliki akses untuk melakukan tindakan ini!', 'error')
                return redirect(url_for('index'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_super_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu!', 'error')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if user is None or not user.is_super_admin:
            flash('Hanya Super Admin yang dapat mengakses halaman ini!', 'error')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login terlebih dahulu!', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
@login_required
def index():
    user = User.query.get(session['user_id'])
    
    if user is None:
        flash('Pengguna tidak ditemukan!', 'error')
        return redirect(url_for('login'))

    total_employees = Employee.query.count()
    active_employees = Employee.query.filter_by(status='Active').count()
    departments = db.session.query(Employee.department).distinct().count()
    
    stats = {
        'total_employees': total_employees,
        'active_employees': active_employees,
        'departments': departments,
        'total_users': User.query.count() if user.has_permission('view_users') else 0
    }
    
    return render_template('index.html', stats=stats, user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role_name
            session['permissions'] = user.role_obj.permissions or []
            session['is_super_admin'] = user.is_super_admin
            flash('Login berhasil!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Username atau password salah, atau akun tidak aktif!', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Cek apakah user sudah login dan memiliki permission create_user
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.has_permission('create_user'):
            # Admin creating new user - allow role selection
            if request.method == 'POST':
                username = request.form['username']
                email = request.form['email']
                password = request.form['password']
                role_id = int(request.form.get('role_id', 3))
                is_active = 'is_active' in request.form
                
                # Super Admin validation
                target_role = Role.query.get(role_id)
                if target_role and target_role.name == 'Super Admin' and not user.is_super_admin:
                    flash('Hanya Super Admin yang dapat membuat user dengan role Super Admin!', 'error')
                    return render_template('add_user.html', roles=Role.query.all())
                
                if User.query.filter_by(username=username).first():
                    flash('Username sudah digunakan!', 'error')
                    return render_template('add_user.html', roles=Role.query.all())
                
                if User.query.filter_by(email=email).first():
                    flash('Email sudah digunakan!', 'error')
                    return render_template('add_user.html', roles=Role.query.all())
                
                user_new = User(
                    username=username,
                    email=email,
                    password_hash=generate_password_hash(password),
                    role_id=role_id,
                    is_active=is_active
                )
                
                db.session.add(user_new)
                db.session.commit()
                
                flash('User berhasil ditambahkan!', 'success')
                return redirect(url_for('users'))
            
            return render_template('add_user.html', roles=Role.query.all())
    
    # Public registration - default Employee role
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username sudah digunakan!', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email sudah digunakan!', 'error')
            return render_template('register.html')
        
        employee_role = Role.query.filter_by(name='Employee').first()
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role_id=employee_role.id if employee_role else 3
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logout berhasil!', 'success')
    return redirect(url_for('login'))

# Employee Management Routes (unchanged)
@app.route('/employees')
@require_permission('view_employees')
def employees():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    department = request.args.get('department', '')
    
    query = Employee.query
    
    if search:
        query = query.filter(Employee.name.contains(search) | 
                           Employee.employee_id.contains(search))
    
    if department:
        query = query.filter_by(department=department)
    
    employees = query.paginate(page=page, per_page=10, error_out=False)
    departments = db.session.query(Employee.department).distinct().all()
    
    user = User.query.get(session['user_id'])
    
    return render_template('employees.html', 
                         employees=employees, 
                         departments=departments,
                         search=search,
                         selected_department=department,
                         user=user)

@app.route('/employee/add', methods=['GET', 'POST'])
@require_permission('create_employee')
def add_employee():
    if request.method == 'POST':
        employee = Employee(
            employee_id=request.form['employee_id'],
            name=request.form['name'],
            email=request.form['email'],
            phone=request.form['phone'],
            department=request.form['department'],
            position=request.form['position'],
            salary=float(request.form['salary']) if request.form['salary'] else None,
            hire_date=datetime.strptime(request.form['hire_date'], '%Y-%m-%d').date(),
            status=request.form['status'],
            created_by=session['user_id']
        )
        
        try:
            db.session.add(employee)
            db.session.commit()
            flash('Karyawan berhasil ditambahkan!', 'success')
            return redirect(url_for('employees'))
        except Exception as e:
            flash('Error: ID Karyawan atau Email sudah digunakan!', 'error')
    
    return render_template('add_employee.html')

@app.route('/employee/edit/<int:id>', methods=['GET', 'POST'])
@require_permission('edit_employee')
def edit_employee(id):
    employee = Employee.query.get_or_404(id)
    
    if request.method == 'POST':
        employee.employee_id = request.form['employee_id']
        employee.name = request.form['name']
        employee.email = request.form['email']
        employee.phone = request.form['phone']
        employee.department = request.form['department']
        employee.position = request.form['position']
        employee.salary = float(request.form['salary']) if request.form['salary'] else None
        employee.hire_date = datetime.strptime(request.form['hire_date'], '%Y-%m-%d').date()
        employee.status = request.form['status']
        employee.updated_at = datetime.utcnow()
        
        try:
            db.session.commit()
            flash('Data karyawan berhasil diupdate!', 'success')
            return redirect(url_for('employees'))
        except Exception as e:
            flash('Error: ID Karyawan atau Email sudah digunakan!', 'error')
    
    return render_template('edit_employee.html', employee=employee)

@app.route('/employee/delete/<int:id>')
@require_permission('delete_employee')
def delete_employee(id):
    employee = Employee.query.get_or_404(id)
    db.session.delete(employee)
    db.session.commit()
    
    flash('Karyawan berhasil dihapus!', 'success')
    return redirect(url_for('employees'))

@app.route('/employee/<int:id>')
@require_permission('view_employees')
def view_employee(id):
    employee = Employee.query.get_or_404(id)
    user = User.query.get(session['user_id'])
    return render_template('view_employee.html', employee=employee, user=user)

# Enhanced User Management Routes
@app.route('/users')
@require_permission('view_users')
def users():
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=10, error_out=False)
    roles = Role.query.all()
    current_user = User.query.get(session['user_id'])
    
    return render_template('users.html', users=users, roles=roles, user=current_user)

@app.route('/user/add')
@require_permission('create_user')
def add_user():
    current_user = User.query.get(session['user_id'])
    # Filter roles - non-super admins can't assign Super Admin role
    if current_user.is_super_admin:
        roles = Role.query.all()
    else:
        roles = Role.query.filter(Role.name != 'Super Admin').all()
    
    return render_template('add_user.html', roles=roles)

@app.route('/user/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    user_to_edit = User.query.get_or_404(id)
    current_user = User.query.get(session['user_id'])
    
    # Access control
    can_edit = False
    can_edit_role = False
    
    if current_user.is_super_admin:
        # Super Admin can edit anyone
        can_edit = True
        can_edit_role = True
    elif current_user.has_permission('edit_user') and id != current_user.id:
        # Other admins can edit other users but not Super Admin accounts
        if user_to_edit.role_name != 'Super Admin':
            can_edit = True
            can_edit_role = True
        else:
            flash('Anda tidak dapat mengedit akun Super Admin!', 'error')
            return redirect(url_for('users'))
    elif id == current_user.id:
        # Users can edit their own profile but not their role
        can_edit = True
        can_edit_role = False
    else:
        flash('Anda tidak memiliki akses untuk mengedit user ini!', 'error')
        return redirect(url_for('users') if current_user.has_permission('view_users') else url_for('index'))
    
    if not can_edit:
        flash('Akses ditolak!', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        user_to_edit.username = request.form['username']
        user_to_edit.email = request.form['email']
        
        # Only allow role changes if user has permission
        if can_edit_role and 'role_id' in request.form:
            new_role_id = int(request.form['role_id'])
            new_role = Role.query.get(new_role_id)
            
            # Additional check: non-super admins can't assign Super Admin role
            if new_role and new_role.name == 'Super Admin' and not current_user.is_super_admin:
                flash('Anda tidak dapat memberikan role Super Admin!', 'error')
            else:
                user_to_edit.role_id = new_role_id
        
        # Only allow active status changes if user has proper permissions
        if can_edit_role and 'is_active' in request.form:
            user_to_edit.is_active = True
        elif can_edit_role:
            user_to_edit.is_active = False
        
        # Change password if provided
        if request.form.get('password'):
            user_to_edit.password_hash = generate_password_hash(request.form['password'])
        
        try:
            db.session.commit()
            flash('Data user berhasil diupdate!', 'success')
            
            # Update session if user edited their own profile
            if id == current_user.id:
                session['username'] = user_to_edit.username
                session['role'] = user_to_edit.role_name
                session['permissions'] = user_to_edit.role_obj.permissions or []
            
            return redirect(url_for('users') if current_user.has_permission('view_users') else url_for('index'))
        except Exception as e:
            flash('Error: Username atau Email sudah digunakan!', 'error')
    
    # Filter roles for non-super admins
    if current_user.is_super_admin:
        roles = Role.query.all()
    else:
        roles = Role.query.filter(Role.name != 'Super Admin').all()
    
    return render_template('edit_user.html', 
                         user_to_edit=user_to_edit, 
                         roles=roles, 
                         user=current_user,
                         can_edit_role=can_edit_role)

@app.route('/user/delete/<int:id>')
@require_permission('delete_user')
def delete_user(id):
    current_user = User.query.get(session['user_id'])
    user_to_delete = User.query.get_or_404(id)
    
    if id == session['user_id']:
        flash('Anda tidak dapat menghapus akun sendiri!', 'error')
        return redirect(url_for('users'))
    
    # Non-super admins cannot delete Super Admin accounts
    if user_to_delete.role_name == 'Super Admin' and not current_user.is_super_admin:
        flash('Anda tidak dapat menghapus akun Super Admin!', 'error')
        return redirect(url_for('users'))
    
    db.session.delete(user_to_delete)
    db.session.commit()
    
    flash('User berhasil dihapus!', 'success')
    return redirect(url_for('users'))

# Role Management Routes (Super Admin only)
@app.route('/roles')
@require_super_admin
def roles():
    roles = Role.query.all()
    current_user = User.query.get(session['user_id'])
    
    available_permissions = [
        'view_dashboard', 'view_employees', 'create_employee', 'edit_employee', 'delete_employee',
        'view_users', 'create_user', 'edit_user', 'delete_user', 'manage_roles'
    ]
    
    return render_template('roles.html', roles=roles, user=current_user, available_permissions=available_permissions)

@app.route('/role/add', methods=['GET', 'POST'])
@require_super_admin
def add_role():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        permissions = request.form.getlist('permissions')
        
        if Role.query.filter_by(name=name).first():
            flash('Nama role sudah digunakan!', 'error')
        else:
            role = Role(
                name=name,
                description=description,
                permissions=permissions,
                is_protected=False
            )
            db.session.add(role)
            db.session.commit()
            flash('Role berhasil ditambahkan!', 'success')
            return redirect(url_for('roles'))
    
    available_permissions = [
        'view_dashboard', 'view_employees', 'create_employee', 'edit_employee', 'delete_employee',
        'view_users', 'create_user', 'edit_user', 'delete_user', 'manage_roles'
    ]
    
    return render_template('add_role.html', available_permissions=available_permissions)

@app.route('/role/edit/<int:id>', methods=['GET', 'POST'])
@require_super_admin
def edit_role(id):
    role = Role.query.get_or_404(id)
    
    # Protect Super Admin role from being modified
    if role.name == 'Super Admin':
        flash('Role Super Admin tidak dapat dimodifikasi!', 'error')
        return redirect(url_for('roles'))
    
    if request.method == 'POST':
        role.name = request.form['name']
        role.description = request.form['description']
        role.permissions = request.form.getlist('permissions')
        
        try:
            db.session.commit()
            flash('Role berhasil diupdate!', 'success')
            return redirect(url_for('roles'))
        except Exception as e:
            flash('Error: Nama role sudah digunakan!', 'error')
    
    available_permissions = [
        'view_dashboard', 'view_employees', 'create_employee', 'edit_employee', 'delete_employee',
        'view_users', 'create_user', 'edit_user', 'delete_user', 'manage_roles'
    ]
    
    return render_template('edit_role.html', role=role, available_permissions=available_permissions)

@app.route('/role/delete/<int:id>')
@require_super_admin
def delete_role(id):
    role = Role.query.get_or_404(id)
    
    # Protect essential roles from deletion
    if role.name in ['Super Admin', 'Employee']:
        flash('Role ini tidak dapat dihapus karena merupakan role sistem!', 'error')
        return redirect(url_for('roles'))
    
    # Check if any users are using this role
    if role.users:
        flash('Tidak dapat menghapus role yang masih digunakan oleh user!', 'error')
        return redirect(url_for('roles'))
    
    db.session.delete(role)
    db.session.commit()
    
    flash('Role berhasil dihapus!', 'success')
    return redirect(url_for('roles'))

# Profile route for users to edit their own profile
@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    return redirect(url_for('edit_user', id=user.id))

# API Endpoints
@app.route('/api/role/<int:role_id>/permissions')
def get_role_permissions(role_id):
    role = Role.query.get_or_404(role_id)
    return jsonify({
        'permissions': role.permissions or [],
        'description': role.description
    })

# Initialize database with default roles and admin user
def init_database():
    db.create_all()
    
    # Create default roles if they don't exist
    roles_data = [
        {
            'name': 'Super Admin',
            'description': 'Full access to all system features',
            'permissions': [
                'view_dashboard', 'view_employees', 'create_employee', 'edit_employee', 'delete_employee',
                'view_users', 'create_user', 'edit_user', 'delete_user', 'manage_roles'
            ],
            'is_protected': True
        },
        {
            'name': 'HR Manager',
            'description': 'Human Resources management access',
            'permissions': [
                'view_dashboard', 'view_employees', 'create_employee', 'edit_employee', 'delete_employee',
                'view_users', 'edit_user'
            ],
            'is_protected': False
        },
        {
            'name': 'Employee',
            'description': 'Basic employee access',
            'permissions': ['view_dashboard', 'view_employees'],
            'is_protected': True
        },
        {
            'name': 'Manager',
            'description': 'Department manager access',
            'permissions': ['view_dashboard', 'view_employees', 'create_employee', 'edit_employee'],
            'is_protected': False
        }
    ]
    
    for role_data in roles_data:
        existing_role = Role.query.filter_by(name=role_data['name']).first()
        if not existing_role:
            role = Role(
                name=role_data['name'],
                description=role_data['description'],
                permissions=role_data['permissions'],
                is_protected=role_data['is_protected']
            )
            db.session.add(role)
    
    db.session.commit()
    
    # Create default admin user
    admin_role = Role.query.filter_by(name='Super Admin').first()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@company.com',
            password_hash=generate_password_hash('admin123'),
            role_id=admin_role.id if admin_role else 1
        )
        db.session.add(admin)
    
    db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        init_database()
    
    app.run(debug=True)

