from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# Instancia de SQLAlchemy, se inicializará en app_test.py
db = SQLAlchemy()

# ===============================================
# 1. MODELO DE USUARIO (SOLO PARA PRUEBAS)
# Mapea a una nueva tabla 'user_test'
# ===============================================
class User(UserMixin, db.Model):
    """Modelo de Usuario para PRUEBAS (admin_test, Luna)."""
    __tablename__ = 'user_test' 
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    
    # Esta relación es solo para el comando init-db-test
    clientes_acceso = db.relationship('UsuarioClienteTest', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # Esta función es clave para la autenticación
        return check_password_hash(self.password_hash, password)

# ===============================================
# 2. MODELO DE CLIENTE/CUIT (EL ORIGINAL)
# Mapea a tu tabla existente 'clientes_afip' (Solo Lectura)
# ===============================================
class Cliente(db.Model):
    """
    Modelo que apunta a tu tabla original 'clientes_afip' para lectura.
    """
    __tablename__ = 'clientes_afip' 
    
    # Asegúrate que estas columnas coincidan con tu MySQL original
    id = db.Column(db.Integer, primary_key=True)
    cuit = db.Column(db.String(11), unique=True, nullable=False)
    razon_social = db.Column(db.String(255), nullable=True)
    

# ===============================================
# 3. MODELO DE RELACIÓN (NUEVA TABLA DE PRUEBA)
# Mapea a la nueva tabla 'usuario_cliente_test'
# ===============================================
class UsuarioClienteTest(db.Model):
    """
    Tabla intermedia de PRUEBAS para la asignación de clientes a usuarios.
    """
    __tablename__ = 'usuario_cliente_test'
    
    id = db.Column(db.Integer, primary_key=True)
    # FK a la tabla de usuarios de prueba (user_test)
    user_id = db.Column(db.Integer, db.ForeignKey('user_test.id'), nullable=False) 
    # FK a la tabla de clientes original (clientes_afip)
    cliente_id = db.Column(db.Integer, db.ForeignKey('clientes_afip.id'), nullable=False) 
    
    user = db.relationship('User', backref='relaciones_test')
    cliente = db.relationship('Cliente', backref='relaciones_test')
    
    __table_args__ = (db.UniqueConstraint('user_id', 'cliente_id', name='_user_cliente_test_uc'),)
