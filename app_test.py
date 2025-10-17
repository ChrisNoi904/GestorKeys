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

# --- LECTURA DE VARIABLES DE ENTORNO ---
DB_HOST = os.environ.get('DB_HOST', 'srv1591.hstgr.io')
DB_NAME = os.environ.get('DB_NAME', 'u822656934_claves_cliente')
DB_USER = os.environ.get('DB_USER', 'u822656934_estudionoya')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'ArielNoya01')
DB_PORT = os.environ.get('DB_PORT', '3306') 

# CONSTRUCCIÓN DE LA URL DE CONEXIÓN A HOSTINGER (Render usará esta URL)
DB_URL_TEST = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'q8mYn_7f2sCj3XR5zT0Lp2E4wK9H_0qA7dFm9oG1vJ6I8uP4yS3xW0uY1rC7eB2')

# Configuración del Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
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
        # Usamos la URL construida a partir de las variables de entorno
        db_params = pymysql.cursors.parse_connect_args(DB_URL_TEST)
        conn = pymysql.connect(cursorclass=pymysql.cursors.DictCursor, **db_params)
        cursor = conn.cursor()
        
        # Leemos de la tabla de PRUEBA
        cursor.execute("SELECT id, username, is_admin FROM user_test WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()

        if user_data:
            user = User(id=user_data['id'], username=user_data['username'], is_admin=user_data['is_admin'])
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
    password_hash = Column(String(128), nullable=False)
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
    """
    Verifica si las tablas de PRUEBA existen y, si no, las crea usando SQLAlchemy.
    Esta función se llama al inicio de la aplicación.
    """
    engine = create_engine(DB_URL_TEST)
    
    # 1. Chequeo de existencia de tabla de prueba (user_test)
    inspector = Inspector.from_engine(engine)
    if 'user_test' in inspector.get_table_names():
        print("✅ Tablas de prueba (user_test) ya existen. Saltando inicialización.")
        return # Ya están creadas, no hacemos nada más.

    # 2. Si no existe, procedemos con la creación y llenado
    print("⏳ Tablas de prueba no encontradas. Iniciando creación y llenado automático...")
    
    Base.metadata.bind = engine
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        # A. Crea las tablas de PRUEBA
        Base.metadata.create_all(engine, tables=[UserTestORM.__table__, UsuarioClienteTestORM.__table__])
        print('    - Tablas de PRUEBA creadas: user_test, usuario_cliente_test.')
        
        # B. Crea la tabla ClienteTestORM solo si no existe, para asegurar la FK
        if 'clientes_afip' not in inspector.get_table_names():
            Base.metadata.create_all(engine, tables=[ClienteTestORM.__table__])
        
        # C. Creación de Usuarios de Prueba
        admin = UserTestORM(username='admin_test', is_admin=True, password_hash=generate_password_hash('123456'))
        luna = UserTestORM(username='Luna', is_admin=False, password_hash=generate_password_hash('123456'))
        session.add_all([admin, luna])
        session.commit()
        session.refresh(luna)
        print('    - Usuarios creados: admin_test/123456 (Admin), Luna/123456 (Restringido).')

        # D. Clientes de Prueba (Solo si no existen en clientes_afip)
        try:
            if session.query(ClienteTestORM).filter_by(id=1).first() is None:
                cliente_1 = ClienteTestORM(id=1, cuit='11111111111', razon_social='Cliente UNO - Asignado a Luna')
                cliente_2 = ClienteTestORM(id=2, cuit='22222222222', razon_social='Cliente DOS - Asignado a Luna')
                cliente_3 = ClienteTestORM(id=3, cuit='33333333333', razon_social='Cliente TRES - Solo Admin')
                session.add_all([cliente_1, cliente_2, cliente_3])
                session.commit()
                print('    - Clientes de prueba insertados en clientes_afip (si no existían).')
        except Exception as e:
            session.rollback()
            print(f'    - Advertencia: No se pudieron insertar clientes de prueba en clientes_afip. {e}')

        # E. Asignación de clientes de prueba a Luna
        acceso_luna_1 = UsuarioClienteTestORM(user_id=luna.id, cliente_id=1)
        acceso_luna_2 = UsuarioClienteTestORM(user_id=luna.id, cliente_id=2)
        session.add_all([acceso_luna_1, acceso_luna_2])
        session.commit()
        print('    - Asignaciones de clientes (1 y 2) creadas para Luna.')
        
    except Exception as e:
        session.rollback()
        print(f'❌ Ocurrió un error IRRECUPERABLE al inicializar la base de datos: {e}')
        # Es CRÍTICO que el inicio no falle por la inicialización.
        
    finally:
        session.close()

# Ejecutar la inicialización automáticamente al inicio
ensure_db_tables_exist()


# =================================================================
#                         RUTAS DE FLASK (USAN PYMYSQL)
# =================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
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

            if user_data and check_password_hash(user_data['password_hash'], password):
                user = User(id=user_data['id'], username=user_data['username'], is_admin=user_data['is_admin'])
                login_user(user)
                flash(f'¡Bienvenido, {username}!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('gestion_claves'))
            else:
                flash('Credenciales inválidas. Por favor, inténtelo de nuevo.', 'error')
                
        except Exception as e:
            print(f"Error en login: {e}") 
            flash('Error interno en la autenticación.', 'error')
        finally:
            if cursor: cursor.close()
            if conn: conn.close()
                
    return render_template('login.html', title='Iniciar Sesión (PRUEBA)')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada correctamente.', 'info')
    return redirect(url_for('login'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('gestion_claves'))
    return redirect(url_for('login'))


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
            
    # Renderiza el template renombrado: gestion_claves_prueba.html
    return render_template('gestion_claves_prueba.html', 
                           clientes=clientes, 
                           filtro_aplicado=filtro_aplicado,
                           usuario_actual=usuario_actual)

# Esta ruta fue agregada para que el ADMIN pueda asignar permisos.
@app.route('/asignar_clientes', methods=['GET', 'POST'])
@login_required
def asignar_clientes():
    # 1. SEGURIDAD: Solo el administrador puede acceder a esta ruta
    if not current_user.is_admin:
        flash("Acceso denegado. Se requiere ser administrador.", 'error')
        return redirect(url_for('gestion_claves'))

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # --- A. Procesar POST (Guardar asignaciones) ---
        if request.method == 'POST':
            # 1. ELIMINAR todas las relaciones existentes para el usuario
            user_id_to_update = request.form.get('user_id')
            if user_id_to_update:
                cursor.execute("DELETE FROM usuario_cliente_test WHERE user_id = %s", (user_id_to_update,))
                
                # 2. INSERTAR las nuevas relaciones
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

        # --- B. Procesar GET (Mostrar formulario) ---
        
        # Obtener todos los usuarios de PRUEBA
        cursor.execute("SELECT id, username, is_admin FROM user_test ORDER BY username")
        users = cursor.fetchall()
        
        # Obtener todos los clientes (de la tabla de PRODUCCIÓN)
        cursor.execute("SELECT id, cuit, razon_social FROM clientes_afip ORDER BY razon_social")
        clientes = cursor.fetchall()
        
        # Obtener las asignaciones actuales
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

# --- Función Auxiliar para Administrar Relaciones ---
def get_user_client_relations(conn):
    """Obtiene todas las relaciones user-cliente existentes para la interfaz de administración."""
    cursor = conn.cursor()
    # Usamos la tabla de relación de PRUEBA
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
    
    # Estructuramos el resultado: {user_id: [cliente_id_1, cliente_id_2], ...}
    for row in cursor.fetchall():
        user_id = row['user_id']
        cliente_id = row['cliente_id']
        if user_id not in relations:
            relations[user_id] = []
        relations[user_id].append(cliente_id)
        
    cursor.close()
    return relations


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
