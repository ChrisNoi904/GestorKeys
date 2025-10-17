import os
import pymysql.cursors 
import json 
import datetime

# --- IMPORTACIONES DE SEGURIDAD Y WEB ---
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash

# --- IMPORTACIONES SOLO PARA LA CREACIÓN INICIAL DE TABLAS (SQLAlchemy temporal) ---
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.engine.reflection import Inspector
# ---------------------------------------------------------------------------------

app = Flask(__name__)

# =================================================================
#                         CONFIGURACIÓN Y GLOBALES
# =================================================================

# --- LECTURA DE VARIABLES DE ENTORNO (Tus credenciales de Hostinger) ---
DB_HOST = os.environ.get('DB_HOST', 'srv1591.hstgr.io')
DB_NAME = os.environ.get('DB_NAME', 'u822656934_claves_cliente')
DB_USER = os.environ.get('DB_USER', 'u822656934_estudionoya')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'ArielNoya01')
DB_PORT = os.environ.get('DB_PORT', '3306') 

# CONSTRUCCIÓN DE LA URL DE CONEXIÓN A HOSTINGER
DB_URL_TEST = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'q8mYn_7f2sCj3XR5zT0Lp2E4wK9H_0qA7dFm9oG1vJ6I8uP4yS3xW0uY1rC7eB2')

# Configuración del Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_prueba' # <--- APUNTA AL LOGIN DE PRUEBA
login_manager.login_message = "Por favor, inicie sesión para acceder a esta página."


# --- CLASE BASE DE USUARIO (SOLO PARA FLASK-LOGIN, NO ORM) ---
class User(UserMixin):
    """Clase que Flask-Login necesita para saber si el usuario está autenticado."""
    def __init__(self, id, username, is_admin):
        self.id = id
        self.username = username
        self.is_admin = is_admin
        
# ------------------------------------------------------------


@login_manager.user_loader
def load_user(user_id):
    """Carga el usuario desde la tabla de prueba 'user_test' usando SQL directo."""
    conn = None
    cursor = None
    user = None
    try:
        db_params = pymysql.cursors.parse_connect_args(DB_URL_TEST)
        conn = pymysql.connect(cursorclass=pymysql.cursors.DictCursor, **db_params)
        cursor = conn.cursor()
        
        # Leemos de la tabla de PRUEBA
        cursor.execute("SELECT id, username, is_admin FROM user_test WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()

        if user_data:
            # Pymysql lee tinyint(1) como bool, lo convertimos a bool si no lo es
            is_admin_bool = bool(user_data['is_admin']) if isinstance(user_data['is_admin'], int) else user_data['is_admin']
            user = User(id=user_data['id'], username=user_data['username'], is_admin=is_admin_bool)
        return user
    except Exception as e:
        print(f"Error al cargar usuario de prueba: {e}") 
        return None
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# Función de conexión a DB (adaptada de tu código original, para consultas directas)
def get_db_connection():
    db_params = pymysql.cursors.parse_connect_args(DB_URL_TEST)
    return pymysql.connect(cursorclass=pymysql.cursors.DictCursor, **db_params)


# =================================================================
#            LÓGICA DE INICIALIZACIÓN AUTOMÁTICA (SQLAlchemy SOLO AQUÍ)
# =================================================================

# Definición de la base y modelos minimalistas SOLO para crear las tablas
Base = declarative_base()

class UserTestORM(Base):
    __tablename__ = 'user_test'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False) # Aumentado a 255 para seguridad de hash
    is_admin = Column(Boolean, default=False)

class ClienteTestORM(Base):
    __tablename__ = 'clientes_afip' # Mapea la tabla existente
    id = Column(Integer, primary_key=True)
    cuit = Column(String(11))
    razon_social = Column(String(255))

class UsuarioClienteTestORM(Base):
    __tablename__ = 'usuario_cliente_test'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user_test.id')) 
    cliente_id = Column(Integer, ForeignKey('clientes_afip.id')) 
    __table_args__ = (UniqueConstraint('user_id', 'cliente_id', name='_user_cliente_test_uc'),)


def ensure_db_tables_exist():
    # NOTA: La lógica de inserción de datos se ha eliminado ya que lo hiciste manualmente con SQL.
    # Solo chequea si las tablas existen para no fallar.
    
    engine = create_engine(DB_URL_TEST)
    inspector = Inspector.from_engine(engine)
    
    if 'user_test' not in inspector.get_table_names() or 'usuario_cliente_test' not in inspector.get_table_names():
        print("ADVERTENCIA: Tablas de prueba incompletas. La aplicación puede fallar si no se insertaron usuarios y relaciones manualmente.")
    else:
        print("✅ Tablas de prueba (user_test, usuario_cliente_test) existen.")

# Ejecutar la inicialización automáticamente al inicio
ensure_db_tables_exist()


# =================================================================
#                         RUTAS DE FLASK (USAN PYMYSQL)
# =================================================================

@app.route('/login_prueba', methods=['GET', 'POST']) 
def login_prueba():
    if current_user.is_authenticated:
        return redirect(url_for('gestion_claves'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = None
        cursor = None
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            sql = "SELECT id, username, password_hash, is_admin FROM user_test WHERE username = %s"
            cursor.execute(sql, (username,))
            user_data = cursor.fetchone()

            if user_data:
                # FIX CRÍTICO: Aseguramos que el hash sea string para la verificación
                password_hash_str = user_data['password_hash'].decode('utf-8') if isinstance(user_data['password_hash'], bytes) else user_data['password_hash']

                if check_password_hash(password_hash_str, password):
                    # Convertimos is_admin a bool
                    is_admin_bool = bool(user_data['is_admin']) if isinstance(user_data['is_admin'], int) else user_data['is_admin']
                    
                    user = User(id=user_data['id'], username=user_data['username'], is_admin=is_admin_bool)
                    login_user(user)
                    flash(f'¡Bienvenido, {username}!', 'success')
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('gestion_claves'))
                else:
                    flash('Credenciales inválidas. Por favor, inténtelo de nuevo.', 'error')
            else:
                 flash('Credenciales inválidas. Por favor, inténtelo de nuevo.', 'error')
                
        except Exception as e:
            # Imprimimos el error real en los logs de Render para depuración
            print(f"--- ERROR CRÍTICO EN LOGIN ---: {e}") 
            flash('Error interno en la autenticación. Consulte los logs de Render.', 'error')
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
                
    return render_template('login_prueba.html', title='Iniciar Sesión (PRUEBA)')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada correctamente.', 'info')
    return redirect(url_for('login_prueba'))


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('gestion_claves'))
    return redirect(url_for('login_prueba'))


@app.route('/gestion_claves')
@login_required
def gestion_claves():
    clientes = []
    usuario_actual = current_user.username
    filtro_aplicado = "No Aplicado"
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if current_user.is_admin:
            # 1. CASO ADMIN: Ve TODOS los clientes de la tabla original
            sql = "SELECT id, cuit, razon_social FROM clientes_afip" 
            cursor.execute(sql)
            clientes = cursor.fetchall()
            filtro_aplicado = "NINGUNO (Acceso total a clientes_afip)"
        else:
            # 2. CASO LUNA (Usuario Restringido): Lógica de filtrado
            filtro_aplicado = f"ASIGNADOS (Filtro por user_id={current_user.id} en usuario_cliente_test)"
            
            # SQL que une la tabla de clientes original con la tabla de relación de PRUEBA
            sql = """
                SELECT 
                    c.id, c.cuit, c.razon_social 
                FROM 
                    clientes_afip c 
                INNER JOIN 
                    usuario_cliente_test uct ON c.id = uct.cliente_id 
                WHERE 
                    uct.user_id = %s
            """
            cursor.execute(sql, (current_user.id,))
            clientes = cursor.fetchall()
            
    except Exception as e:
        print(f"Error al cargar clientes en gestion_claves: {e}") 
        flash('Error al cargar la lista de clientes.', 'error')
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
            
    # RENDERIZA EL TEMPLATE CORRECTO
    return render_template('gestion_claves_prueba.html', 
                           clientes=clientes, 
                           filtro_aplicado=filtro_aplicado,
                           usuario_actual=usuario_actual)

def get_user_client_relations(conn):
    """Obtiene todas las relaciones user-cliente existentes para la interfaz de administración."""
    cursor = conn.cursor()
    sql = """
        SELECT 
            uct.user_id, 
            uct.cliente_id, 
            u.username, 
            c.razon_social
        FROM 
            usuario_cliente_test uct
        INNER JOIN 
            user_test u ON u.id = uct.user_id
        INNER JOIN 
            clientes_afip c ON c.id = uct.cliente_id
    """
    cursor.execute(sql)
    relations = {}
    for row in cursor.fetchall():
        user_id = row['user_id']
        cliente_id = row['cliente_id']
        if user_id not in relations:
            relations[user_id] = []
        relations[user_id].append(cliente_id)
        
    cursor.close()
    return relations


@app.route('/asignar_clientes', methods=['GET', 'POST'])
@login_required
def asignar_clientes():
    if not current_user.is_admin:
        flash("Acceso denegado. Se requiere ser administrador.", 'error')
        return redirect(url_for('gestion_claves'))

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if request.method == 'POST':
            user_id_to_update = request.form.get('user_id')
            if user_id_to_update:
                # 1. ELIMINAR asignaciones previas
                cursor.execute("DELETE FROM usuario_cliente_test WHERE user_id = %s", (user_id_to_update,))
                
                # 2. INSERTAR nuevas asignaciones
                clientes_asignados = request.form.getlist('clientes_asignados')
                for cliente_id in clientes_asignados:
                    sql_insert = """
                        INSERT INTO usuario_cliente_test (user_id, cliente_id) 
                        VALUES (%s, %s)
                    """
                    cursor.execute(sql_insert, (user_id_to_update, cliente_id))
                
                conn.commit()
                flash(f'Permisos actualizados para el usuario ID {user_id_to_update} con {len(clientes_asignados)} clientes.', 'success')
                return redirect(url_for('asignar_clientes'))

        cursor.execute("SELECT id, username, is_admin FROM user_test ORDER BY username")
        users = cursor.fetchall()
        
        cursor.execute("SELECT id, cuit, razon_social FROM clientes_afip ORDER BY razon_social")
        clientes = cursor.fetchall()
        
        relaciones_actuales = get_user_client_relations(conn)
        
    except Exception as e:
        print(f"Error en la ruta /asignar_clientes: {e}") 
        flash('Error al cargar la interfaz de administración.', 'error')
        users = []
        clientes = []
        relaciones_actuales = {}
    finally:
        if cursor: cursor.close()
        if conn: conn.close()
            
    return render_template('asignar_clientes.html', 
                           users=users, 
                           clientes=clientes, 
                           relaciones_actuales=relaciones_actuales)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
