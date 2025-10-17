import os
import pymysql.cursors 
import json 
import datetime

# --- IMPORTACIONES DE SEGURIDAD Y WEB ---
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash

# --- IMPORTACIONES SOLO PARA LA CREACIÓN INICIAL DE TABLAS ---
# Necesitamos estas librerías SOLO para el comando 'init-db-test'
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.orm import relationship
# -----------------------------------------------------------

app = Flask(__name__)

# =================================================================
#                         CONFIGURACIÓN Y GLOBALES
# =================================================================

# ** AJUSTAR ESTA URL **
DB_URL_TEST = os.environ.get(
    'DATABASE_URL', 
    'mysql+pymysql://root:password@localhost/u822656934_claves_cliente' 
)
app.config['SECRET_KEY'] = 'clave_secreta_solo_para_prueba_muy_larga_y_segura' 

# Configuración del Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message = "Por favor, inicie sesión para acceder a esta página."


# --- CLASE BASE DE USUARIO (SOLO PARA FLASK-LOGIN) ---
# Esta clase NO interactúa con la DB, solo la necesita Flask-Login
class User(UserMixin):
    def __init__(self, id, username, is_admin):
        self.id = id
        self.username = username
        self.is_admin = is_admin
        
# -----------------------------------------------------


@login_manager.user_loader
def load_user(user_id):
    """
    Carga el usuario desde la tabla de prueba 'user_test' usando SQL directo (pymysql).
    """
    conn = None
    cursor = None
    user = None
    try:
        db_params = pymysql.cursors.parse_connect_args(DB_URL_TEST)
        conn = pymysql.connect(cursorclass=pymysql.cursors.DictCursor, **db_params)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, is_admin FROM user_test WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()

        if user_data:
            # Creamos una instancia de la clase User (no ORM)
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
#                         RUTAS DE AUTENTICACIÓN
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
            
            # Consultar la tabla de prueba 'user_test'
            sql = "SELECT id, username, password_hash, is_admin FROM user_test WHERE username = %s"
            cursor.execute(sql, (username,))
            user_data = cursor.fetchone()

            if user_data and check_password_hash(user_data['password_hash'], password):
                # Crear la instancia del modelo User (no ORM)
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


# =================================================================
#           RUTA DE GESTIÓN DE CLAVES (LÓGICA CENTRAL FILTRADA)
# =================================================================

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


# =================================================================
# COMANDO CLI DE INICIALIZACIÓN DE TABLAS Y DATOS (USA SQLALCHEMY)
# ESTA ES LA ÚNICA PARTE QUE USA EL ORM PARA LA CREACIÓN INICIAL
# =================================================================

# Definición de la base para SQLAlchemy (solo para este comando)
Base = declarative_base()

# Definición de modelos minimalistas SOLO para crear las tablas de prueba
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


@app.cli.command('init-db-test')
def init_db_command():
    """
    Crea las tablas de PRUEBA (user_test y usuario_cliente_test) y datos iniciales.
    """
    print("--- INICIANDO AMBIENTE DE PRUEBA CAUTELAR ---")
    
    # 1. Configurar Conexión para SQLAlchemy
    engine = create_engine(DB_URL_TEST)
    Base.metadata.bind = engine
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        # Crea las tablas de PRUEBA (si no existen)
        Base.metadata.create_all(engine, tables=[UserTestORM.__table__, UsuarioClienteTestORM.__table__])
        print('Tablas de PRUEBA (user_test, usuario_cliente_test) creadas/actualizadas.')

        # Crea la tabla ClienteTestORM solo si no existe para asegurar IDs de prueba
        if not engine.dialect.has_table(engine, 'clientes_afip'):
            Base.metadata.create_all(engine, tables=[ClienteTestORM.__table__])
        
        # === CREACIÓN DE DATOS DE PRUEBA ===
        
        # 1. Usuarios de Prueba
        if session.query(UserTestORM).filter_by(username='admin_test').first() is None:
            admin = UserTestORM(username='admin_test', is_admin=True, password_hash=generate_password_hash('123456'))
            luna = UserTestORM(username='Luna', is_admin=False, password_hash=generate_password_hash('123456'))
            session.add_all([admin, luna])
            session.commit()
            print('Usuarios admin_test y Luna creados en user_test (Contraseña: 123456).')
            session.refresh(luna) # Refrescar para obtener el ID de Luna
        else:
            luna = session.query(UserTestORM).filter_by(username='Luna').first()

        # 2. Clientes de Prueba (Solo si no existen en clientes_afip)
        # Usamos el ORM de forma cautelosa aquí.
        try:
            if session.query(ClienteTestORM).filter_by(id=1).first() is None:
                cliente_1 = ClienteTestORM(id=1, cuit='11111111111', razon_social='Cliente UNO - Asignado a Luna')
                cliente_2 = ClienteTestORM(id=2, cuit='22222222222', razon_social='Cliente DOS - Asignado a Luna')
                cliente_3 = ClienteTestORM(id=3, cuit='33333333333', razon_social='Cliente TRES - Solo Admin')
                session.add_all([cliente_1, cliente_2, cliente_3])
                session.commit()
                print('Clientes de prueba 1, 2, 3 creados en clientes_afip.')
        except Exception:
            session.rollback()
            print("Clientes de prueba ya existen en clientes_afip o la tabla ya tiene datos.")


        # 3. Asignación de clientes de prueba a Luna
        if luna and luna.id:
            try:
                # Intentar crear las relaciones si no existen
                if session.query(UsuarioClienteTestORM).filter_by(user_id=luna.id, cliente_id=1).first() is None:
                    acceso_luna_1 = UsuarioClienteTestORM(user_id=luna.id, cliente_id=1)
                    session.add(acceso_luna_1)
                if session.query(UsuarioClienteTestORM).filter_by(user_id=luna.id, cliente_id=2).first() is None:
                    acceso_luna_2 = UsuarioClienteTestORM(user_id=luna.id, cliente_id=2)
                    session.add(acceso_luna_2)
                    
                session.commit()
                print(f'Relaciones de acceso creadas/verificadas: Luna tiene acceso a Clientes ID 1 y 2.')
            except Exception as e:
                session.rollback()
                print(f'Error al crear relaciones de acceso: {e}')
        
    except Exception as e:
        session.rollback()
        print(f'Ocurrió un error IRRECUPERABLE al inicializar la base de datos de prueba: {e}')
    finally:
        session.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
