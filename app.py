import os
import subprocess
import datetime
import time
import tempfile
import pathlib
import sys
import base64
import ssl # Importar módulo SSL para la validación del certificado
from xml.etree import ElementTree as ET

# Librerías necesarias para la migración
from flask import Flask, render_template, request, redirect, url_for, flash
import pymysql
from zeep import Client
from zeep.transports import Transport
from openpyxl import load_workbook

# NOTA IMPORTANTE: Se eliminaron las importaciones de cryptography que generaban el error

# =================================================================
#                         CONFIGURACIÓN Y GLOBALES
# =================================================================

# CUIT Emisor (se mantiene fijo o se gestiona como variable de entorno)
CUIT_EMISOR = 20216732716

# Servicios AFIP
WSAA_WSDL = "https://wsaa.afip.gov.ar/ws/services/LoginCms?wsdl"
PADRON_WSDL = "https://aws.afip.gov.ar/sr-padron/webservices/personaServiceA5?WSDL"
SERVICE_ID = "ws_sr_constancia_inscripcion"

# Archivo Excel de claves (solo para carga inicial si es necesario)
CLAVES_FILE = pathlib.Path(__file__).parent / "claves.xlsx"

# --- Configuración de Base de Datos (Desde Variables de Entorno de Render) ---
DB_HOST = os.environ.get("DB_HOST", "srv1591.hstgr.io") 
DB_USER = os.environ.get("DB_USER", "tu_usuario_hostinger") 
DB_PASSWORD = os.environ.get("DB_PASSWORD", "tu_contraseña_hostinger") 
DB_NAME = os.environ.get("DB_NAME", "u822656934_claves_cliente")
DB_PORT = int(os.environ.get("DB_PORT", 3306))

# --- Configuración del binario OpenSSL ---
OPENSSL_BIN = "openssl" 

# Inicializar Flask
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "una_clave_secreta_fuerte") 

# =================================================================
#                         FUNCIONES DE BASE DE DATOS
# =================================================================

def get_db_connection():
    """Establece la conexión a la base de datos MySQL."""
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT,
            cursorclass=pymysql.cursors.DictCursor
        )
        return conn
    except Exception as e:
        app.logger.error(f"Error al conectar a la base de datos: {e}")
        flash(f"Error de conexión a la DB: {e}", 'error')
        return None

# =================================================================
#                         LÓGICA AFIP (ADAPTADA A LA DB)
# =================================================================

def obtener_certificados_activos():
    """Recupera el contenido de los certificados activos de la DB."""
    conn = get_db_connection()
    if not conn: return None, None
    try:
        with conn.cursor() as cursor:
            # Selecciona el certificado activo y más reciente
            sql = "SELECT cert_content, key_content FROM certificados WHERE activo = 1 ORDER BY fecha_alta DESC LIMIT 1"
            cursor.execute(sql)
            result = cursor.fetchone()
            return (result['cert_content'], result['key_content']) if result else (None, None)
    except Exception as e:
        app.logger.error(f"Error al obtener certificados: {e}")
        return None, None
    finally:
        conn.close()


def consultar_cuit_afip(cuit_consultado_str):
    """
    Función que maneja toda la lógica de conexión y consulta AFIP.
    Utiliza los contenidos de certificado/key directamente desde la DB.
    """
    
    cuit_consultado_str = cuit_consultado_str.strip()
    
    if not cuit_consultado_str.isdigit() or len(cuit_consultado_str) not in (11, 10):
        return None, "CUIT inválido."

    cert_content, key_content = obtener_certificados_activos()
    if not cert_content or not key_content:
        return None, "No se encontraron certificados AFIP activos en la base de datos."

    # Creamos archivos temporales en el sistema de archivos de Render (/tmp)
    # Escribimos los contenidos binarios de la DB a archivos temporales para que OpenSSL pueda usarlos
    with tempfile.NamedTemporaryFile(delete=False) as tmp_cert, \
         tempfile.NamedTemporaryFile(delete=False) as tmp_key, \
         tempfile.NamedTemporaryFile(mode='w', delete=False, encoding="utf-8") as tmp_lt, \
         tempfile.NamedTemporaryFile(delete=False) as tmp_cms_der:

        # Escribir el contenido binario en los archivos temporales
        tmp_cert.write(cert_content)
        tmp_key.write(key_content)
        
        tmp_cert_path = tmp_cert.name
        tmp_key_path = tmp_key.name
        tmp_lt_path = tmp_lt.name
        tmp_cms_der_path = tmp_cms_der.name

        # --- 1. CREAR LoginTicketRequest ---
        ahora = datetime.datetime.now()
        generation_time = (ahora - datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S")
        expiration_time = (ahora + datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S")

        login_ticket = f"""<?xml version="1.0" encoding="UTF-8"?>
<loginTicketRequest version="1.0">
  <header>
    <uniqueId>{int(time.time())}</uniqueId>
    <generationTime>{generation_time}</generationTime>
    <expirationTime>{expiration_time}</expirationTime>
  </header>
  <service>{SERVICE_ID}</service>
</loginTicketRequest>"""
        tmp_lt.write(login_ticket)
        tmp_lt.close() # Asegurarse de que el archivo se haya escrito

        try:
            # --- 2. FIRMAR EL TICKET (CMS) ---
            subprocess.check_call([
                OPENSSL_BIN, 'smime', '-sign',
                '-in', tmp_lt_path,
                '-signer', tmp_cert_path,
                '-inkey', tmp_key_path,
                '-outform', 'DER',
                '-nodetach', '-binary',
                '-out', tmp_cms_der_path
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            cms_der = pathlib.Path(tmp_cms_der_path).read_bytes()
            cms_b64 = subprocess.check_output([OPENSSL_BIN, 'base64'], input=cms_der).decode().strip()
            
            # --- 3. AUTENTICAR EN WSAA ---
            client_wsaa = Client(WSAA_WSDL, transport=Transport(timeout=20))
            ta_response = client_wsaa.service.loginCms(cms_b64)

            root_xml = ET.fromstring(ta_response) if isinstance(ta_response, str) else ET.fromstring(ET.tostring(ta_response, encoding="utf-8"))

            token = root_xml.findtext(".//token")
            sign = root_xml.findtext(".//sign")

            if not token or not sign:
                return None, "Error de AFIP: No se pudo obtener token/sign del TA."
            
            # --- 4. CONSULTAR PADRÓN AFIP ---
            client_padron = Client(PADRON_WSDL, transport=Transport(timeout=20))
            respuesta = client_padron.service.getPersona_v2(token, sign, CUIT_EMISOR, int(cuit_consultado_str))

            # --- 5. PROCESAR RESPUESTA ---
            persona = getattr(respuesta, "personaReturn", respuesta)
            if persona is None:
                return None, f"CUIT {cuit_consultado_str} no encontrado o sin datos."

            dg = persona.datosGenerales
            nombre_capturado = getattr(dg, 'razonSocial', "") or f"{getattr(dg, 'nombre', '')} {getattr(dg, 'apellido', '')}".strip()
            
            return persona, nombre_capturado

        except subprocess.CalledProcessError as e:
            return None, f"Error de OpenSSL al firmar: {e}"
        except Exception as e:
            return None, f"Error en la consulta AFIP: {e}"
        finally:
            # Eliminar archivos temporales
            os.unlink(tmp_cert_path)
            os.unlink(tmp_key_path)
            os.unlink(tmp_lt_path)
            os.unlink(tmp_cms_der_path)

# =================================================================
#                         RUTAS FLASK
# =================================================================

# --- Página de inicio/Consulta CUIT ---
@app.route('/', methods=['GET', 'POST'])
def index():
    consulta_cuit = None
    razon_social = None
    error_message = None

    if request.method == 'POST':
        if 'cuit_consulta' in request.form:
            cuit_consulta = request.form['cuit_consulta']
            
            # Realizar consulta AFIP
            persona_data, mensaje_error = consultar_cuit_afip(cuit_consulta)
            
            if mensaje_error and persona_data is None:
                error_message = mensaje_error
            else:
                consulta_cuit = cuit_consulta
                razon_social = persona_data.datosGenerales.razonSocial
                
                # Pre-formatear el resultado para la web
                resultado_html = format_afip_result_html(persona_data, consulta_cuit)
                
                # Si se solicitó guardar el cliente
                if request.form.get('guardar_cliente'):
                    if save_client_to_db(consulta_cuit, razon_social):
                        flash(f"Cliente {razon_social} ({consulta_cuit}) guardado exitosamente.", 'success')
                    else:
                        flash(f"El cliente {cuit_consulta} ya estaba registrado.", 'info')
                
                return render_template('index.html', 
                                       resultado_html=resultado_html, 
                                       cuit_consultado=consulta_cuit,
                                       razon_social=razon_social)
        
        elif 'carga_inicial' in request.form:
            # Carga Inicial de Excel (opcional y solo para migrar datos)
            if load_data_from_excel():
                flash("Datos de clientes y claves migrados correctamente a la DB.", 'success')
            else:
                flash("Error al migrar datos de Excel. ¿Existen los archivos?", 'error')
            
            return redirect(url_for('index'))

    return render_template('index.html', error_message=error_message)

# --- Gestión de Claves ---
@app.route('/gestion_claves', methods=['GET', 'POST'])
@app.route('/gestion_claves/<cuit>', methods=['GET', 'POST'])
def gestion_claves(cuit=None):
    conn = get_db_connection()
    if not conn: return redirect(url_for('index'))

    clientes = []
    claves = []
    
    try:
        with conn.cursor() as cursor:
            # Obtener lista de clientes
            cursor.execute("SELECT cuit, razon_social FROM clientes_afip ORDER BY razon_social")
            clientes = cursor.fetchall()
            
            if cuit:
                # Obtener claves para el CUIT seleccionado
                sql = "SELECT id, descripcion_clave, usuario, clave FROM claves WHERE cuit = %s"
                cursor.execute(sql, (cuit,))
                claves = cursor.fetchall()
            
            # Lógica para agregar/editar/eliminar claves
            if request.method == 'POST':
                action = request.form.get('action')
                if action == 'add' and cuit:
                    desc = request.form['desc']
                    user = request.form['user']
                    pw = request.form['pw']
                    sql = "INSERT INTO claves (cuit, descripcion_clave, usuario, clave) VALUES (%s, %s, %s, %s)"
                    cursor.execute(sql, (cuit, desc, user, pw))
                    flash("Clave agregada.", 'success')
                
                elif action == 'update' and cuit:
                    key_id = request.form['key_id']
                    desc = request.form['desc']
                    user = request.form['user']
                    pw = request.form['pw']
                    sql = "UPDATE claves SET descripcion_clave=%s, usuario=%s, clave=%s WHERE id=%s AND cuit=%s"
                    cursor.execute(sql, (desc, user, pw, key_id, cuit))
                    flash("Clave actualizada.", 'success')

                elif action == 'delete' and cuit:
                    key_id = request.form['key_id']
                    sql = "DELETE FROM claves WHERE id=%s AND cuit=%s"
                    cursor.execute(sql, (key_id, cuit))
                    flash("Clave eliminada.", 'success')
                
                conn.commit()
                return redirect(url_for('gestion_claves', cuit=cuit))

    except Exception as e:
        flash(f"Error de DB en gestión de claves: {e}", 'error')
    finally:
        conn.close()

    return render_template('gestion_claves.html', clientes=clientes, claves=claves, cuit_seleccionado=cuit)

# --- Gestión de Certificados ---
@app.route('/gestion_certificados', methods=['GET', 'POST'])
def gestion_certificados():
    conn = get_db_connection()
    if not conn: return redirect(url_for('index'))

    tmp_cert_path = None # Inicializar para el bloque finally
    
    try:
        if request.method == 'POST':
            if 'cert_file' in request.files and 'key_file' in request.files:
                cert_file = request.files['cert_file']
                key_file = request.files['key_file']
                
                if cert_file and key_file:
                    cert_content = cert_file.read()
                    key_content = key_file.read()
                    
                    # 1. Validar y obtener vencimiento (NUEVA LÓGICA CON SSL)
                    try:
                        # Crear un archivo temporal para el certificado en el sistema de archivos
                        with tempfile.NamedTemporaryFile(delete=False) as tmp_cert:
                            tmp_cert.write(cert_content)
                            tmp_cert_path = tmp_cert.name
                        
                        # Usar la función interna de ssl para decodificar la información del certificado
                        cert_data = ssl._ssl._test_decode_cert(tmp_cert_path)
                        vencimiento_str = cert_data['notAfter']
                        
                        # Convertir la fecha de formato 'MMM DD HH:MM:SS YYYY GMT' a objeto date
                        vencimiento = datetime.datetime.strptime(vencimiento_str, '%b %d %H:%M:%S %Y GMT').date()
                        
                    except Exception as e:
                        flash(f"Error al leer el certificado (.crt) usando SSL. Asegúrese que sea un certificado X.509 válido en formato PEM y sin cifrar: {e}", 'error')
                        return redirect(url_for('gestion_certificados'))

                    # 2. Desactivar todos los certificados anteriores
                    with conn.cursor() as cursor:
                        cursor.execute("UPDATE certificados SET activo = 0")
                        
                        # 3. Insertar el nuevo certificado
                        sql = "INSERT INTO certificados (fecha_alta, fecha_vencimiento, nombre_archivo, cert_content, key_content, activo) VALUES (%s, %s, %s, %s, %s, 1)"
                        cursor.execute(sql, (datetime.datetime.now(), vencimiento, cert_file.filename, cert_content, key_content))
                        conn.commit()
                        flash(f"Certificado {cert_file.filename} cargado y activado. Vence el {vencimiento}.", 'success')
                    
                    return redirect(url_for('gestion_certificados'))

            elif 'delete_id' in request.form:
                cert_id = request.form['delete_id']
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM certificados WHERE id = %s", (cert_id,))
                    conn.commit()
                    flash("Certificado eliminado del historial.", 'success')

        # Obtener historial de certificados
        with conn.cursor() as cursor:
            # Obtener la fecha de hoy para el template
            today = datetime.date.today()
            
            cursor.execute("SELECT id, fecha_alta, fecha_vencimiento, nombre_archivo, activo FROM certificados ORDER BY fecha_vencimiento DESC")
            certificados = cursor.fetchall()
            
    except Exception as e:
        flash(f"Error en la gestión de certificados: {e}", 'error')
        certificados = []
        today = datetime.date.today()
    finally:
        # Asegurarse de que el archivo temporal se elimine
        if tmp_cert_path and os.path.exists(tmp_cert_path):
            os.unlink(tmp_cert_path)
        if conn: conn.close()

    return render_template('gestion_certificados.html', certificados=certificados, today=today)

# =================================================================
#                         FUNCIONES CRUD/AUXILIARES
# =================================================================

def save_client_to_db(cuit, razon_social):
    """Guarda un cliente en la tabla clientes_afip si no existe."""
    conn = get_db_connection()
    if not conn: return False
    
    try:
        with conn.cursor() as cursor:
            # Verificar si existe
            cursor.execute("SELECT cuit FROM clientes_afip WHERE cuit = %s", (cuit,))
            if cursor.fetchone():
                return False # Ya existe

            # Insertar
            sql = "INSERT INTO clientes_afip (cuit, razon_social) VALUES (%s, %s)"
            cursor.execute(sql, (cuit, razon_social))
            conn.commit()
            return True
    except Exception as e:
        app.logger.error(f"Error al guardar cliente: {e}")
        return False
    finally:
        conn.close()


def load_data_from_excel():
    """Carga inicial de datos de clientes y claves desde archivos locales (solo para la migración inicial)."""
    if not CLAVES_FILE.exists():
        return False

    conn = None
    try:
        wb = load_workbook(CLAVES_FILE)
        ws = wb["Hoja1"]
        headers = [str(cell.value).lower().strip() if cell.value is not None else '' for cell in ws[1]]
        
        required_fields = ['cuit', 'descripcion_clave', 'usuario', 'clave']
        if not all(field in headers for field in required_fields):
             return False

        cuit_idx = headers.index('cuit')
        desc_idx = headers.index('descripcion_clave')
        user_idx = headers.index('usuario')
        clave_idx = headers.index('clave')

        conn = get_db_connection()
        if not conn: return False

        with conn.cursor() as cursor:
            for row in ws.iter_rows(min_row=2, values_only=True):
                if row and len(row) > max(cuit_idx, desc_idx, user_idx, clave_idx):
                    cuit = str(row[cuit_idx]).strip().replace('-', '').replace(' ', '')
                    razon_social = "Desconocida (Desde Excel)" # Se puede mejorar si se usa otro archivo
                    
                    if cuit.isdigit() and len(cuit) >= 10:
                        # 1. Insertar Cliente (ignorar duplicados)
                        try:
                            cursor.execute("INSERT IGNORE INTO clientes_afip (cuit, razon_social) VALUES (%s, %s)", (cuit, razon_social))
                        except Exception:
                            pass # Ignoramos si ya existe

                        # 2. Insertar Clave
                        desc = str(row[desc_idx]).strip()
                        user = str(row[user_idx]).strip()
                        pw = str(row[clave_idx]).strip()
                        
                        sql = "INSERT INTO claves (cuit, descripcion_clave, usuario, clave) VALUES (%s, %s, %s, %s)"
                        cursor.execute(sql, (cuit, desc, user, pw))
            
            conn.commit()
            return True
    except Exception as e:
        app.logger.error(f"Error al cargar datos de Excel: {e}")
        return False
    finally:
        if conn: conn.close()


def format_afip_result_html(persona, cuit):
    """Formatea la respuesta del servicio AFIP a una cadena HTML legible."""
    if persona is None: return "No se recibieron datos de AFIP."
    
    html = f"<h2>Resultado de la Consulta AFIP (CUIT: {cuit})</h2>"
    
    dg = persona.datosGenerales
    nombre_capturado = getattr(dg, 'razonSocial', "") or f"{getattr(dg, 'nombre', '')} {getattr(dg, 'apellido', '')}".strip()

    html += f"<h3>Datos Generales</h3>"
    html += f"<p><strong>Razón Social/Nombre:</strong> {nombre_capturado or '—'}</p>"
    html += f"<p><strong>Estado Clave:</strong> {dg.estadoClave}</p>"
    dom = dg.domicilioFiscal
    html += f"<p><strong>Domicilio Fiscal:</strong> {dom.direccion} | {dom.localidad} | {dom.descripcionProvincia} | CP: {dom.codPostal}</p>"
    
    return html

if __name__ == '__main__':
    # Usar un puerto dinámico en Render
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
