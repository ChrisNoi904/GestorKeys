import os
import pymysql.cursors 
import json 
import datetime

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, render_template, request, redirect, url_for, flash
from sqlalchemy import create_engine # Necesario solo para el comando init-db-test
from sqlalchemy.orm import sessionmaker # Necesario solo para el comando init-db-test

# Importamos los modelos de prueba. Necesitas models_test.py en el mismo directorio.
from .models_test import db, User, Cliente, UsuarioClienteTest 

app = Flask(__name__)

# =================================================================
#                         CONFIGURACIÓN Y GLOBALES
# =================================================================

# ** ADAPTA ESTA URL ** con las credenciales de tu ambiente de prueba MySQL.
# Por ejemplo: 'mysql+pymysql://user:password@hostinger_ip:3306/nombre_bd'
DB_URL_TEST = os.environ.get(
    'DATABASE_URL', 
    'mysql+pymysql://root:password@localhost/u822656934_claves_cliente' 
)
app.config['SECRET_KEY'] = 'clave_secreta_solo_para_prueba_muy_larga_y_segura' 

# Configuración del Login Manager para la tabla de prueba (user_test)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 
login_manager.login_message = "Por favor, inicie sesión para acceder a esta página."

@login_manager.user_loader
def load_user(user_id):
    """
    Carga el usuario desde la tabla de prueba 'user_test' usando SQL directo.
    """
    conn = None
    cursor = None
    try:
        # Extraer parámetros de conexión de la URL
        db_params = pymysql.cursors.parse_connect_args(DB_URL_TEST)
        conn = pymysql.connect(cursorclass=pymysql.cursors.DictCursor, **db_params)
        cursor = conn.cursor()
        
        # Consultar la tabla de prueba 'user_test'
        cursor.execute("SELECT id, username, password_hash, is_admin FROM user_test WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()

        if user_data:
            # Creamos una instancia del modelo User de prueba (necesario para flask_login)
            user = User(id=user_data['id'], username=user_data['username'], is_admin=user_data['is_admin'])
            user.password_hash = user_data['password_hash']
            return user
        return None
    except Exception as e:
        # Aquí se debería usar el logger real de la app
        print(f"Error al cargar usuario de prueba: {e}") 
        return None
    finally:
        if cursor: cursor.close()
        if conn: conn.close()


# Función de conexión a DB (adaptada de tu código original, para consultas directas)
def get_db_connection():
    # Extraer parámetros de conexión de la URL
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
            cursor.execute("SELECT id, username, password_hash, is_admin FROM user_test WHERE username = %s", (username,))
            user_data = cursor.fetchone()

            if user_data and check_password_hash(user_data['password_hash'], password):
                # Crear la instancia del modelo User de prueba
                user = User(id=user_data['id'], username=user_data['username'], is_admin=user_data['is_admin'])
                login_user(user)
                flash(f'¡Bienvenido, {username}!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('gestion_claves'))
            else:
                flash('Credenciales inválidas. Por favor, inténtelo de nuevo.', 'error')
                
        except Exception as e:
            # Aquí se debería usar el logger real de la app
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
            # Se asume que la tabla original es 'clientes_afip'
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
        # Aquí se debería usar el logger real de la app
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
# Ejecutar: 'flask --app app_test init-db-test'
# =================================================================
@app.cli.command('init-db-test')
def init_db_command():
    """
    Crea las tablas de PRUEBA (user_test y usuario_cliente_test) y datos iniciales.
    ATENCIÓN: Esto usa SQLAlchemy temporalmente para la creación de tablas.
    """
    print("--- INICIANDO AMBIENTE DE PRUEBA CAUTELAR ---")
    
    # 1. Configurar DB para SQLAlchemy (solo para create_all)
    app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL_TEST
    db.init_app(app)

    with app.app_context():
        try:
            # Crea las tablas de PRUEBA
            db.create_all() 
            print('Tablas de PRUEBA (user_test, usuario_cliente_test) creadas/actualizadas.')

            # === CREACIÓN DE DATOS DE PRUEBA ===
            if not User.query.filter_by(username='admin_test').first():
                admin = User(username='admin_test', is_admin=True)
                admin.set_password('123456') 
                luna = User(username='Luna', is_admin=False)
                luna.set_password('123456') 
                db.session.add_all([admin, luna])
                db.session.commit()
                print('Usuarios admin_test y Luna creados en user_test (Contraseña: 123456).')
            
            # Asegurar que existan clientes de prueba en la tabla original
            try:
                if not Cliente.query.filter_by(id=1).first():
                    cliente_1 = Cliente(id=1, cuit='11111111111', razon_social='Cliente UNO - Asignado a Luna')
                    cliente_2 = Cliente(id=2, cuit='22222222222', razon_social='Cliente DOS - Asignado a Luna')
                    cliente_3 = Cliente(id=3, cuit='33333333333', razon_social='Cliente TRES - Solo Admin')
                    db.session.add_all([cliente_1, cliente_2, cliente_3])
                    db.session.commit()
                    print('Clientes de prueba 1, 2, 3 creados en clientes_afip.')
            except Exception:
                db.session.rollback()

            # Asignación de clientes de prueba a Luna
            luna_obj = User.query.filter_by(username='Luna').first()
            cliente_id_1 = 1 
            cliente_id_2 = 2
            
            if luna_obj:
                try:
                    # Intenta crear las relaciones
                    acceso_luna_1 = UsuarioClienteTest(user_id=luna_obj.id, cliente_id=cliente_id_1)
                    acceso_luna_2 = UsuarioClienteTest(user_id=luna_obj.id, cliente_id=cliente_id_2)
                    db.session.add_all([acceso_luna_1, acceso_luna_2])
                    db.session.commit()
                    print(f'Relaciones de acceso creadas: Luna tiene acceso a Clientes ID {cliente_id_1} y {cliente_id_2}.')
                except Exception:
                    db.session.rollback()
                    print('Relaciones de acceso ya existen. No se crearon duplicados.')
            else:
                print("Error: No se pudo encontrar el usuario 'Luna'.")
                
        except Exception as e:
            db.session.rollback()
            print(f'Ocurrió un error IRRECUPERABLE al inicializar la base de datos de prueba: {e}')
