from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from flask_mail import Mail, Message
from database import init_db, get_db_connection
from functools import wraps
import os
import requests
import uuid
from datetime import datetime, date, timedelta
from werkzeug.utils import secure_filename
import re
import sqlite3
import bcrypt
import logging

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False
    security_logger = logging.getLogger('security')
    if security_logger:
        security_logger.warning("Flask-Limiter no está instalado. Rate limiting limitado.")

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24).hex())

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
security_logger = logging.getLogger('security')

try:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )
except Exception as e:
    security_logger.warning(f"Flask-Limiter no disponible: {str(e)}")
    limiter = None

app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://webpay3gint.transbank.cl https://webpay3g.transbank.cl https://api.mercadopago.com https://cdn.jsdelivr.net;"
    )
    return response

@app.template_filter('formato_precio_clp')
def formato_precio_clp(value):
    try:
        precio = float(value)
        precio_formateado = f"{precio:,.0f}".replace(",", ".")
        return f"${precio_formateado}"
    except (ValueError, TypeError):
        return f"${value}"

WEBPAY_ENVIRONMENT = os.getenv('WEBPAY_ENVIRONMENT', 'INTEGRACION')
WEBPAY_COMMERCE_CODE = os.getenv('WEBPAY_COMMERCE_CODE', '597055555532')
WEBPAY_API_KEY = os.getenv('WEBPAY_API_KEY', '579B532A7440BB0C9079DED94D31EA1615BACEB56610332264630D42D0A36B1C')

if WEBPAY_ENVIRONMENT == 'PRODUCCION':
    WEBPAY_URL = 'https://webpay3g.transbank.cl'
else:
    WEBPAY_URL = 'https://webpay3gint.transbank.cl'

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'tu_email@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'tu_contraseña')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'vent@vent.cl')

mail = Mail(app)

MP_ACCESS_TOKEN = os.getenv('MP_ACCESS_TOKEN', 'tu_access_token_mercadopago')
try:
    if MP_ACCESS_TOKEN != 'tu_access_token_mercadopago':
        import mercadopago
        mp = mercadopago.SDK(MP_ACCESS_TOKEN)
    else:
        mp = None
except ImportError:
    mp = None
    print("Mercado Pago SDK no está instalado. Ejecuta: pip install mercadopago")

COSTO_ENVIO_FIJO = 5000

def create_tables():
    init_db()

create_tables()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# En Vercel solo /tmp es escribible; en local usamos static/img
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or (
    os.path.join('/tmp', 'uploads') if os.environ.get('VERCEL') else os.path.join(BASE_DIR, 'static', 'img')
)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validar_email(email):
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def sanitizar_texto(texto, max_length=500):
    if not texto:
        return ''
    texto = str(texto)[:max_length]
    texto = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', texto)
    return texto.strip()

@app.route('/')
def index():
    return render_template('index.html')

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def registrar_intento_login(ip_address, usuario, exitoso):
    try:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO intentos_login (ip_address, usuario, exitoso)
            VALUES (?, ?, ?)
        ''', (ip_address, usuario, 1 if exitoso else 0))
        conn.commit()
        conn.close()
    except Exception as e:
        security_logger.error(f"Error al registrar intento de login: {str(e)}")

def verificar_bloqueo_ip(ip_address):
    try:
        conn = get_db_connection()
        # Contar intentos fallidos en los últimos 15 minutos
        hace_15_min = datetime.now() - timedelta(minutes=15)
        intentos = conn.execute('''
            SELECT COUNT(*) FROM intentos_login
            WHERE ip_address = ? AND exitoso = 0 AND fecha > ?
        ''', (ip_address, hace_15_min)).fetchone()[0]
        conn.close()
        
        # Bloquear después de 5 intentos fallidos en 15 minutos
        return intentos >= 5
    except Exception as e:
        security_logger.error(f"Error al verificar bloqueo IP: {str(e)}")
        return False

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        usuario = request.form.get('usuario', '').strip()
        password = request.form.get('password', '').strip()
        ip_address = get_client_ip()
        
        # Validación básica de entrada
        if not usuario or not password:
            registrar_intento_login(ip_address, usuario or 'unknown', False)
            return render_template('admin/login.html', error='Por favor completa todos los campos.')
        
        # Verificar bloqueo por IP
        if verificar_bloqueo_ip(ip_address):
            security_logger.warning(f"Intento de login bloqueado desde IP: {ip_address}")
            registrar_intento_login(ip_address, usuario, False)
            return render_template('admin/login.html', 
                                error='Demasiados intentos fallidos desde esta IP. Por favor intenta en 15 minutos.')
        
        # Sanitizar entrada
        usuario = sanitizar_texto(usuario, max_length=50)
        password = sanitizar_texto(password, max_length=200)
        
        # Validar formato de usuario (solo alfanumérico y guiones bajos)
        if not re.match(r'^[a-zA-Z0-9_]+$', usuario):
            registrar_intento_login(ip_address, usuario, False)
            return render_template('admin/login.html', error='Usuario inválido.')
        
        # Buscar usuario en la base de datos
        conn = get_db_connection()
        try:
            user = conn.execute('''
                SELECT * FROM usuarios_admin 
                WHERE usuario = ? AND activo = 1
            ''', (usuario,)).fetchone()
            
            if not user:
                # Usuario no existe - simular tiempo de verificación para prevenir enumeración
                try:
                    bcrypt.checkpw(b'dummy', bcrypt.gensalt())  # Dummy check para timing
                except:
                    pass
                registrar_intento_login(ip_address, usuario, False)
                security_logger.warning(f"Intento de login con usuario inexistente: {usuario} desde IP: {ip_address}")
                conn.close()
                return render_template('admin/login.html', error='Usuario o contraseña incorrectos.')
            
            # Verificar si la cuenta está bloqueada
            if user['bloqueado_hasta']:
                bloqueado_hasta = datetime.strptime(user['bloqueado_hasta'], '%Y-%m-%d %H:%M:%S')
                if datetime.now() < bloqueado_hasta:
                    tiempo_restante = bloqueado_hasta - datetime.now()
                    minutos = int(tiempo_restante.total_seconds() / 60)
                    registrar_intento_login(ip_address, usuario, False)
                    security_logger.warning(f"Intento de login en cuenta bloqueada: {usuario} desde IP: {ip_address}")
                    conn.close()
                    return render_template('admin/login.html', 
                                        error=f'Cuenta bloqueada. Intenta nuevamente en {minutos} minutos.')
                else:
                    # Desbloquear cuenta si ya pasó el tiempo
                    conn.execute('''
                        UPDATE usuarios_admin 
                        SET bloqueado_hasta = NULL, intentos_fallidos = 0
                        WHERE id = ?
                    ''', (user['id'],))
                    conn.commit()
            
            # Verificar contraseña
            try:
                password_bytes = password.encode('utf-8')
                password_hash_bytes = user['password_hash'].encode('utf-8')
                
                if bcrypt.checkpw(password_bytes, password_hash_bytes):
                    # Login exitoso
                    session.permanent = True
                    session['admin_logged_in'] = True
                    session['admin_user_id'] = user['id']
                    session['admin_username'] = user['usuario']
                    session['last_activity'] = datetime.now().isoformat()
                    
                    # Actualizar último acceso y resetear intentos fallidos
                    conn.execute('''
                        UPDATE usuarios_admin 
                        SET ultimo_acceso = CURRENT_TIMESTAMP, intentos_fallidos = 0
                        WHERE id = ?
                    ''', (user['id'],))
                    conn.commit()
                    conn.close()
                    
                    registrar_intento_login(ip_address, usuario, True)
                    security_logger.info(f"Login exitoso: {usuario} desde IP: {ip_address}")
                    
                    return redirect(url_for('admin_index'))
                else:
                    # Contraseña incorrecta
                    intentos_fallidos = user['intentos_fallidos'] + 1
                    
                    # Bloquear cuenta después de 5 intentos fallidos
                    if intentos_fallidos >= 5:
                        bloqueado_hasta = datetime.now() + timedelta(minutes=30)
                        conn.execute('''
                            UPDATE usuarios_admin 
                            SET intentos_fallidos = ?, bloqueado_hasta = ?
                            WHERE id = ?
                        ''', (intentos_fallidos, bloqueado_hasta, user['id']))
                        security_logger.warning(f"Cuenta bloqueada por múltiples intentos fallidos: {usuario} desde IP: {ip_address}")
                        conn.commit()
                        conn.close()
                        registrar_intento_login(ip_address, usuario, False)
                        return render_template('admin/login.html', 
                                            error='Demasiados intentos fallidos. Cuenta bloqueada por 30 minutos.')
                    else:
                        conn.execute('''
                            UPDATE usuarios_admin 
                            SET intentos_fallidos = ?
                            WHERE id = ?
                        ''', (intentos_fallidos, user['id']))
                        conn.commit()
                        conn.close()
                    
                    registrar_intento_login(ip_address, usuario, False)
                    security_logger.warning(f"Intento de login fallido: {usuario} desde IP: {ip_address}")
                    return render_template('admin/login.html', error='Usuario o contraseña incorrectos.')
            
            except Exception as e:
                security_logger.error(f"Error al verificar contraseña: {str(e)}")
                registrar_intento_login(ip_address, usuario, False)
                conn.close()
                return render_template('admin/login.html', error='Error al procesar el login. Por favor intenta nuevamente.')
        
        except Exception as e:
            security_logger.error(f"Error en login: {str(e)}")
            conn.close()
            return render_template('admin/login.html', error='Error al procesar el login. Por favor intenta nuevamente.')
    
    return render_template('admin/login.html')

@app.route('/admin/crear-usuario', methods=['GET', 'POST'])
def admin_crear_usuario():
    """Crea el primer usuario admin (solo en despliegue). Protegido por CREATE_ADMIN_TOKEN."""
    token = os.environ.get('CREATE_ADMIN_TOKEN')
    if not token or token.strip() == '':
        # Ruta desactivada: no revelar que existe (404 genérico)
        return render_template('404.html'), 404
    # Token puede ir en query (?token=xxx) o en form (campo oculto)
    req_token = request.args.get('token') or (request.form.get('token') if request.method == 'POST' else None)
    if req_token != token:
        # Token incorrecto o faltante: mismo 404 para no revelar la ruta
        return render_template('404.html'), 404
    if request.method == 'POST':
        usuario = request.form.get('usuario', '').strip()
        password = request.form.get('password', '').strip()
        password_confirm = request.form.get('password_confirm', '').strip()
        email = request.form.get('email', '').strip() or None
        if not usuario or not re.match(r'^[a-zA-Z0-9_]+$', usuario):
            return render_template('admin/crear_usuario.html', error='Usuario inválido (solo letras, números y _).', token=token)
        if len(password) < 8:
            return render_template('admin/crear_usuario.html', error='La contraseña debe tener al menos 8 caracteres.', token=token)
        if password != password_confirm:
            return render_template('admin/crear_usuario.html', error='Las contraseñas no coinciden.', token=token)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO usuarios_admin (usuario, password_hash, email, activo)
                VALUES (?, ?, ?, 1)
            ''', (usuario, password_hash, email))
            conn.commit()
            conn.close()
            return redirect(url_for('admin_login'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('admin/crear_usuario.html', error=f'El usuario "{usuario}" ya existe.', token=token)
        except Exception as e:
            conn.close()
            return render_template('admin/crear_usuario.html', error=f'Error: {str(e)}', token=token)
    return render_template('admin/crear_usuario.html', token=token)

@app.route('/inicio')
def inicio():
    return redirect(url_for('index'))

@app.route('/tienda')
def tienda():
    # Verificar si la tienda está habilitada
    if not seccion_habilitada('tienda'):
        mensaje = obtener_mensaje_seccion('tienda')
        return render_template('seccion_cerrada.html', seccion='TIENDA', mensaje=mensaje), 503
    
    # Obtener categoría del parámetro de la URL
    categoria = request.args.get('categoria', 'nuevo').lower()
    
    conn = get_db_connection()
    
    # Filtrar productos por categoría (solo activos)
    if categoria == 'nuevo':
        # Mostrar todos los productos activos ordenados por ID descendente (más recientes primero)
        productos = conn.execute('SELECT * FROM productos WHERE activo = 1 ORDER BY id DESC').fetchall()
    elif categoria == 'ropa':
        # Filtrar productos de ropa - solo los que tienen categoría 'ropa' explícitamente (no NULL, no vacío)
        productos = conn.execute('''
            SELECT * FROM productos 
            WHERE activo = 1 
            AND categoria IS NOT NULL
            AND categoria = 'ropa'
            AND categoria != ''
            ORDER BY id DESC
        ''').fetchall()
    elif categoria == 'accesorios':
        # Filtrar accesorios - solo los que tienen categoría 'accesorios' explícitamente (no NULL, no vacío)
        productos = conn.execute('''
            SELECT * FROM productos 
            WHERE activo = 1 
            AND categoria IS NOT NULL
            AND categoria = 'accesorios'
            AND categoria != ''
            ORDER BY id DESC
        ''').fetchall()
    else:
        # Por defecto, mostrar todos los productos activos
        productos = conn.execute('SELECT * FROM productos WHERE activo = 1 ORDER BY id DESC').fetchall()
    
    conn.close()
    
    # Obtener información del carrito para el contador
    carrito = session.get('carrito', [])
    cantidad_carrito = sum(item['cantidad'] for item in carrito)
    
    # Obtener término de búsqueda si existe
    busqueda = request.args.get('busqueda', '').strip()
    
    return render_template('tienda.html', productos=productos, cantidad_carrito=cantidad_carrito, categoria=categoria, busqueda=busqueda)

@app.route('/producto/<int:id>')
def producto(id):
    conn = get_db_connection()
    producto = conn.execute('SELECT * FROM productos WHERE id = ? AND activo = 1', (id,)).fetchone()
    
    # Verificar y corregir estructura de tabla tallas si es necesario
    try:
        # Intentar obtener TODAS las tallas, incluso sin stock
        tallas = conn.execute('''
            SELECT talla, stock 
            FROM tallas 
            WHERE producto_id = ?
            ORDER BY 
                CASE talla
                    WHEN 'Talla Única' THEN 0
                    WHEN 'S' THEN 1
                    WHEN 'M' THEN 2
                    WHEN 'L' THEN 3
                    WHEN 'XL' THEN 4
                    ELSE 5
                END
        ''', (id,)).fetchall()
    except sqlite3.OperationalError as e:
        # Si falta la columna stock, agregarla
        if 'no such column: stock' in str(e).lower():
            try:
                conn.execute('ALTER TABLE tallas ADD COLUMN stock INTEGER DEFAULT 0')
                conn.commit()
                # Reintentar la consulta - mostrar TODAS las tallas, incluso sin stock
                tallas = conn.execute('''
                    SELECT talla, stock 
                    FROM tallas 
                    WHERE producto_id = ?
                    ORDER BY 
                        CASE talla
                            WHEN 'Talla Única' THEN 0
                            WHEN 'S' THEN 1
                            WHEN 'M' THEN 2
                            WHEN 'L' THEN 3
                            WHEN 'XL' THEN 4
                            ELSE 5
                        END
                ''', (id,)).fetchall()
            except sqlite3.OperationalError:
                tallas = []
        else:
            tallas = []
    
    if not tallas:
        # Verificar si existe talla única
        try:
            talla_unica = conn.execute('SELECT * FROM tallas WHERE producto_id = ? AND talla = ?', (id, 'Talla Única')).fetchone()
            if not talla_unica:
                stock_producto = producto['stock'] if producto else 0
                conn.execute('INSERT INTO tallas (producto_id, talla, stock) VALUES (?, ?, ?)', (id, 'Talla Única', stock_producto))
                conn.commit()
                tallas = conn.execute('SELECT talla, stock FROM tallas WHERE producto_id = ?', (id,)).fetchall()
        except sqlite3.OperationalError:
            # Si la tabla no tiene la columna stock, usar solo talla
            try:
                tallas = conn.execute('SELECT talla FROM tallas WHERE producto_id = ?', (id,)).fetchall()
                # Convertir a formato con stock
                tallas = [{'talla': t[0], 'stock': 0} for t in tallas]
            except:
                tallas = []
    
    total_productos = conn.execute('SELECT COUNT(*) FROM productos WHERE activo = 1').fetchone()[0]
    
    # Obtener productos relacionados (misma categoría, excluyendo el producto actual)
    productos_relacionados = []
    if producto:
        categoria_producto = producto['categoria'] or 'ropa'
        productos_relacionados = conn.execute('''
            SELECT * FROM productos 
            WHERE activo = 1 
            AND id != ? 
            AND (categoria = ? OR categoria IS NULL)
            ORDER BY id DESC 
            LIMIT 4
        ''', (id, categoria_producto)).fetchall()
        
        # Si no hay productos de la misma categoría, mostrar otros productos
        if not productos_relacionados:
            productos_relacionados = conn.execute('''
                SELECT * FROM productos 
                WHERE activo = 1 
                AND id != ? 
                ORDER BY id DESC 
                LIMIT 4
            ''', (id,)).fetchall()
    
    conn.close()
    
    if not producto:
        return redirect(url_for('tienda'))
    
    return render_template('producto.html', producto=producto, tallas=tallas, total_productos=total_productos, productos_relacionados=productos_relacionados)

@app.route('/galeria')
def galeria():
    # Verificar si la galería está habilitada
    if not seccion_habilitada('galeria'):
        mensaje = obtener_mensaje_seccion('galeria')
        return render_template('seccion_cerrada.html', seccion='GALERÍA', mensaje=mensaje), 503
    
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM galeria ORDER BY fecha DESC').fetchall()
    conn.close()
    
    return render_template('galeria.html', items=items)

@app.route('/archivo')
def archivo():
    if not seccion_habilitada('archivo'):
        mensaje = obtener_mensaje_seccion('archivo')
        return render_template('seccion_cerrada.html', seccion='ARCHIVO', mensaje=mensaje), 503
    
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM archivo ORDER BY fecha DESC').fetchall()
    conn.close()
    return render_template('archivo.html', items=items)

@app.route('/archive')
def archive():
    return redirect(url_for('archivo'))

@app.route('/nosotros')
def nosotros():
    if not seccion_habilitada('nosotros'):
        mensaje = obtener_mensaje_seccion('nosotros')
        return render_template('seccion_cerrada.html', seccion='NOSOTROS', mensaje=mensaje), 503
    
    return render_template('nosotros.html')

@app.route('/about')
def about():
    return redirect(url_for('nosotros'))

@app.route('/contacto')
def contacto():
    if not seccion_habilitada('contacto'):
        mensaje = obtener_mensaje_seccion('contacto')
        return render_template('seccion_cerrada.html', seccion='CONTACTO', mensaje=mensaje), 503
    
    return render_template('contacto.html')

@app.route('/contact')
def contact():
    return redirect(url_for('contacto'))

@app.route('/privacidad')
def privacidad():
    return render_template('privacidad.html')

@app.route('/privacy')
def privacy():
    return redirect(url_for('privacidad'))

@app.route('/terminos')
def terminos():
    return render_template('terminos.html')

@app.route('/terms')
def terms():
    return redirect(url_for('terminos'))

@app.route('/carrito')
def carrito():
    # Obtener carrito de la sesión
    carrito = session.get('carrito', [])
    
    # Si el carrito está vacío, intentar cargar desde localStorage (vía parámetro)
    # Esto se manejará desde el frontend
    
    # Calcular subtotal
    total_subtotal = sum(item['precio'] * item['cantidad'] for item in carrito)
    
    # Obtener datos de envío de la sesión si existen
    datos_envio = session.get('datos_envio', {})
    tipo_envio = datos_envio.get('tipo_envio', 'retiro')
    # Solo usar costo_envio si ya fue calculado explícitamente
    costo_envio = datos_envio.get('costo_envio') if datos_envio.get('costo_envio') is not None else 0
    
    # Obtener información del cupón si existe
    cupon_info = session.get('cupon_aplicado', {})
    descuento = cupon_info.get('descuento', 0) if cupon_info else 0
    
    # Calcular total
    total = total_subtotal - descuento + costo_envio
    if total < 0:
        total = 0
    
    return render_template('carrito.html', 
                         carrito=carrito, 
                         total_subtotal=total_subtotal,
                         tipo_envio=tipo_envio,
                         costo_envio=costo_envio,
                         descuento=descuento,
                         cupon_info=cupon_info,
                         total=total,
                         datos_envio=datos_envio)

@app.route('/agregar_carrito', methods=['POST'])
def agregar_carrito():
    try:
        # No requiere login para agregar al carrito
        
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Content-Type debe ser application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Datos JSON inválidos'}), 400
        
        producto_id = data.get('producto_id')
        cantidad = data.get('cantidad', 1)
        talla = data.get('talla', 'Talla Única')
        
        if producto_id is None:
            return jsonify({'success': False, 'error': 'producto_id es requerido'}), 400
        
        if not talla:
            return jsonify({'success': False, 'error': 'talla es requerida'}), 400
        
        # Convertir producto_id a int si es necesario
        try:
            producto_id = int(producto_id)
        except (ValueError, TypeError):
            return jsonify({'success': False, 'error': 'producto_id debe ser un número'}), 400
        
        # Validar stock de la talla
        conn = get_db_connection()
        talla_stock = conn.execute('''
            SELECT stock FROM tallas WHERE producto_id = ? AND talla = ?
        ''', (producto_id, talla)).fetchone()
        
        if not talla_stock:
            conn.close()
            return jsonify({'success': False, 'error': f'La talla {talla} no está disponible para este producto'}), 400
        
        stock_disponible = talla_stock['stock']
        
        # Verificar stock disponible
        carrito = session.get('carrito', [])
        cantidad_en_carrito = sum(
            item['cantidad'] for item in carrito 
            if item.get('id') == producto_id and item.get('talla') == talla
        )
        
        if cantidad_en_carrito + cantidad > stock_disponible:
            conn.close()
            return jsonify({
                'success': False, 
                'error': f'Stock insuficiente. Disponible: {stock_disponible - cantidad_en_carrito} unidades'
            }), 400
        
        conn.close()
        
        # Verificar si el producto con la misma talla ya está en el carrito
        producto_existente = next(
            (p for p in carrito if p['id'] == producto_id and p.get('talla') == talla), 
            None
        )
        
        if producto_existente:
            producto_existente['cantidad'] += cantidad
        else:
            # Intentar obtener de la base de datos primero
            try:
                conn = get_db_connection()
                producto = conn.execute('SELECT * FROM productos WHERE id = ?', (producto_id,)).fetchone()
                conn.close()
                
                if producto:
                    # Usar datos de la base de datos
                    carrito.append({
                        'id': producto['id'],
                        'nombre': producto['nombre'],
                        'precio': float(producto['precio']),
                        'imagen': producto['imagen'] if producto['imagen'] else '/static/img/prueba.galeria.png',
                        'talla': talla,
                        'cantidad': cantidad
                    })
                else:
                    # Si no está en la BD, usar los datos enviados desde el frontend
                    nombre = data.get('nombre', 'Producto')
                    precio = float(data.get('precio', 0))
                    imagen = data.get('imagen', '/static/img/prueba.galeria.png')
                    
                    carrito.append({
                        'id': producto_id,
                        'nombre': nombre,
                        'precio': precio,
                        'imagen': imagen,
                        'talla': talla,
                        'cantidad': cantidad
                    })
            except Exception as e:
                # Si hay error con la BD, usar datos del frontend
                nombre = data.get('nombre', 'Producto')
                precio = float(data.get('precio', 0))
                imagen = data.get('imagen', '/static/img/prueba.galeria.png')
                
                carrito.append({
                    'id': producto_id,
                    'nombre': nombre,
                    'precio': precio,
                    'imagen': imagen,
                    'cantidad': cantidad
                })
        
        session['carrito'] = carrito
        
        # Calcular cantidad total
        cantidad_total = sum(item['cantidad'] for item in carrito)
        
        return jsonify({'success': True, 'carrito': carrito, 'cantidad_total': cantidad_total})
    
    except Exception as e:
        print(f"Error en agregar_carrito: {str(e)}")
        return jsonify({'success': False, 'error': f'Error del servidor: {str(e)}'}), 500

@app.route('/actualizar_cantidad', methods=['POST'])
def actualizar_cantidad():
    
    data = request.json
    producto_id = data.get('producto_id')
    cambio = data.get('cambio', 0)
    
    carrito = session.get('carrito', [])
    
    for item in carrito:
        if item['id'] == producto_id:
            nueva_cantidad = item['cantidad'] + cambio
            if nueva_cantidad <= 0:
                carrito.remove(item)
            else:
                item['cantidad'] = nueva_cantidad
            break
    
    session['carrito'] = carrito
    return jsonify({'success': True})

@app.route('/eliminar_producto', methods=['POST'])
def eliminar_producto():
    
    data = request.json
    producto_id = data.get('producto_id')
    
    carrito = session.get('carrito', [])
    carrito = [item for item in carrito if item['id'] != producto_id]
    
    session['carrito'] = carrito
    return jsonify({'success': True})

@app.route('/guardar_datos_envio', methods=['POST'])
def guardar_datos_envio():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'error': 'Content-Type debe ser application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Datos JSON inválidos'}), 400
        
        # Validar y sanitizar datos de entrada
        nombre = sanitizar_texto(data.get('nombre', ''), max_length=200)
        email = data.get('email', '').strip().lower() if data.get('email') else ''
        telefono = sanitizar_texto(data.get('telefono', ''), max_length=20)
        tipo_envio = data.get('tipo_envio', 'retiro')
        
        # Validar tipo de envío
        if tipo_envio not in ['retiro', 'envio']:
            return jsonify({'success': False, 'error': 'Tipo de envío inválido'}), 400
        
        # Calcular costo de envío (precio fijo)
        costo_envio = 0
        
        if tipo_envio == 'envio':
            # Validar datos de envío solo si se requiere calcular
            direccion = sanitizar_texto(data.get('direccion', ''), max_length=300)
            comuna = sanitizar_texto(data.get('comuna', ''), max_length=100)
            region = sanitizar_texto(data.get('region', ''), max_length=100)
            
            # Si faltan datos de envío pero se está calculando, solo validar comuna y región
            if not comuna or not region:
                return jsonify({'success': False, 'error': 'Por favor completa la comuna y región para calcular el envío'}), 400
            
            # Usar costo fijo de envío
            costo_envio = COSTO_ENVIO_FIJO
        else:
            direccion = sanitizar_texto(data.get('direccion', ''), max_length=300) if data.get('direccion') else ''
            comuna = sanitizar_texto(data.get('comuna', ''), max_length=100) if data.get('comuna') else ''
            region = sanitizar_texto(data.get('region', ''), max_length=100) if data.get('region') else ''
            costo_envio = 0
        
        # Guardar datos en sesión (guardar todos los datos proporcionados, validación estricta solo al pagar)
        datos_guardar = {
            'tipo_envio': tipo_envio,
            'costo_envio': float(costo_envio)  # Asegurar que es float
        }
        
        # Agregar datos de dirección solo si están presentes y no están vacíos
        if direccion and direccion.strip():
            datos_guardar['direccion'] = direccion.strip()
        if comuna and comuna.strip():
            datos_guardar['comuna'] = comuna.strip()
        if region and region.strip():
            datos_guardar['region'] = region.strip()
        
        # Agregar datos de contacto si están presentes (sin validación estricta para el cálculo)
        if nombre and nombre.strip():
            datos_guardar['nombre'] = nombre.strip()
        
        if email and email.strip():
            datos_guardar['email'] = email.strip()
        
        if telefono and telefono.strip():
            datos_guardar['telefono'] = telefono.strip()
        
        # Actualizar sesión con los datos existentes más los nuevos
        datos_existentes = session.get('datos_envio', {})
        datos_existentes.update(datos_guardar)
        session['datos_envio'] = datos_existentes
        
        # Asegurar que la sesión se guarde
        session.modified = True
        
        return jsonify({'success': True, 'costo_envio': float(costo_envio)})
    
    except Exception as e:
        print(f"Error en guardar_datos_envio: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'Error al procesar los datos: {str(e)}'}), 500

def procesar_pago_exitoso(metodo_pago, payment_id=None, datos_pago=None):
    carrito = session.get('carrito', [])
    datos_envio = session.get('datos_envio', {})
    
    if not carrito:
        return redirect(url_for('pago_finalizado', estado='error'))
    
    # Calcular totales
    subtotal = sum(item['precio'] * item['cantidad'] for item in carrito)
    costo_envio = datos_envio.get('costo_envio', 0)
    
    # Obtener descuento del cupón si existe
    cupon_info = session.get('cupon_aplicado', {})
    descuento = cupon_info.get('descuento', 0) if cupon_info else 0
    cupon_id = cupon_info.get('cupon_id') if cupon_info else None
    codigo_cupon = cupon_info.get('codigo') if cupon_info else None
    
    total = subtotal - descuento + costo_envio
    if total < 0:
        total = 0
    
    # Generar número de pedido único
    numero_pedido = f"VENT-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Preparar datos de pago
    datos_pago_str = str(datos_pago) if datos_pago else f'{{"payment_id": "{payment_id}", "metodo": "{metodo_pago}"}}'
    
    # Insertar pedido
    cursor.execute('''
        INSERT INTO pedidos (numero_pedido, usuario_email, usuario_nombre, usuario_telefono,
                          tipo_envio, direccion, comuna, region, costo_envio, subtotal, descuento, total, metodo_pago, estado, datos_pago, cupon_id, codigo_cupon)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        numero_pedido,
        datos_envio.get('email', ''),
        datos_envio.get('nombre', ''),
        datos_envio.get('telefono', ''),
        datos_envio.get('tipo_envio', 'retiro'),
        datos_envio.get('direccion', ''),
        datos_envio.get('comuna', ''),
        datos_envio.get('region', ''),
        costo_envio,
        subtotal,
        descuento,
        total,
        metodo_pago,
        'pendiente',
        datos_pago_str,
        cupon_id,
        codigo_cupon
    ))
    pedido_id = cursor.lastrowid
    
    # Insertar items del pedido
    for item in carrito:
        talla = item.get('talla', 'Talla Única')
        cursor.execute('''
            INSERT INTO pedido_items (pedido_id, producto_id, producto_nombre, talla, cantidad, precio)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (pedido_id, item['id'], item['nombre'], talla, item['cantidad'], item['precio']))
        
        # Actualizar stock de la talla
        if talla:
            cursor.execute('''
                UPDATE tallas 
                SET stock = stock - ? 
                WHERE producto_id = ? AND talla = ?
            ''', (item['cantidad'], item['id'], talla))
    
    # Incrementar usos del cupón si se aplicó
    if cupon_id:
        cursor.execute('''
            UPDATE cupones SET usos_actuales = usos_actuales + 1 WHERE id = ?
        ''', (cupon_id,))
    
    conn.commit()
    
    # Obtener pedido completo para el correo
    pedido = conn.execute('SELECT * FROM pedidos WHERE id = ?', (pedido_id,)).fetchone()
    items = conn.execute('SELECT * FROM pedido_items WHERE pedido_id = ?', (pedido_id,)).fetchall()
    conn.close()
    
    # Enviar correo con boleta
    try:
        enviar_boleta_correo(pedido, items, carrito)
    except Exception as e:
        print(f"Error al enviar correo: {str(e)}")
    
    # Limpiar sesión
    session['carrito'] = []
    session.pop('datos_envio', None)
    session.pop('cupon_aplicado', None)
    session.pop('metodo_pago', None)
    session['pago_exitoso'] = True
    session['numero_pedido'] = numero_pedido
    
    return redirect(url_for('pago_finalizado', estado='aprobado', pedido_id=pedido_id))

@app.route('/iniciar_pago_mercadopago', methods=['POST'])
def iniciar_pago_mercadopago():
    carrito = session.get('carrito', [])
    if not carrito:
        return jsonify({'success': False, 'error': 'El carrito está vacío'}), 400
    
    # Validar datos de envío
    datos_envio = session.get('datos_envio', {})
    if not datos_envio.get('nombre') or not datos_envio.get('email'):
        return jsonify({'success': False, 'error': 'Por favor completa los datos de contacto'}), 400
    
    # Calcular totales
    subtotal = sum(item['precio'] * item['cantidad'] for item in carrito)
    costo_envio = datos_envio.get('costo_envio', 0)
    total = subtotal + costo_envio
    
    if not mp:
        return jsonify({'success': False, 'error': 'Mercado Pago no está configurado correctamente'}), 500
    
    try:
        # Crear preferencia de pago en Mercado Pago
        items = []
        for item in carrito:
            items.append({
                "title": item['nombre'],
                "quantity": item['cantidad'],
                "unit_price": float(item['precio'])
            })
        
        # Agregar costo de envío si aplica
        if costo_envio > 0:
            items.append({
                "title": "Costo de Envío",
                "quantity": 1,
                "unit_price": float(costo_envio)
            })
        
        preference_data = {
            "items": items,
            "payer": {
                "name": datos_envio.get('nombre', ''),
                "email": datos_envio.get('email', ''),
                "phone": {
                    "number": datos_envio.get('telefono', '')
                }
            },
            "back_urls": {
                "success": request.url_root.rstrip('/') + url_for('confirmar_pago_mercadopago', status='success'),
                "failure": request.url_root.rstrip('/') + url_for('confirmar_pago_mercadopago', status='failure'),
                "pending": request.url_root.rstrip('/') + url_for('confirmar_pago_mercadopago', status='pending')
            },
            "auto_return": "approved",
            "external_reference": str(uuid.uuid4())
        }
        
        preference = mp.preference().create(preference_data)
        
        if preference and preference.get("status") == 201:
            # Guardar información en sesión
            session['mp_preference_id'] = preference["response"]["id"]
            session['mp_external_reference'] = preference_data["external_reference"]
            session['metodo_pago'] = 'mercadopago'
            
            # Redirigir a Mercado Pago
            init_point = preference["response"]["init_point"]
            return jsonify({'success': True, 'url': init_point})
        else:
            error_msg = 'Error al crear la preferencia de pago en Mercado Pago'
            if preference and 'message' in preference:
                error_msg += ': ' + str(preference.get('message'))
            return jsonify({'success': False, 'error': error_msg}), 500
    
    except Exception as e:
        print(f"Error en Mercado Pago: {str(e)}")
        return jsonify({'success': False, 'error': f'Error al procesar el pago con Mercado Pago: {str(e)}'}), 500

@app.route('/confirmar_pago_mercadopago')
def confirmar_pago_mercadopago():
    status = request.args.get('status', 'failure')
    payment_id = request.args.get('payment_id')
    preference_id = request.args.get('preference_id')
    
    if status == 'success' or status == 'approved':
        # Pago exitoso - procesar igual que Webpay
        return procesar_pago_exitoso('mercadopago', payment_id)
    else:
        return redirect(url_for('pago_finalizado', estado='rechazado'))

@app.route('/iniciar_pago_webpay', methods=['POST'])
def iniciar_pago_webpay():
    carrito = session.get('carrito', [])
    if not carrito:
        return redirect(url_for('carrito'))
    
    # Validar datos de envío
    datos_envio = session.get('datos_envio', {})
    if not datos_envio.get('nombre') or not datos_envio.get('email'):
        return jsonify({'success': False, 'error': 'Por favor completa los datos de contacto'}), 400
    
    # Calcular totales
    subtotal = sum(item['precio'] * item['cantidad'] for item in carrito)
    costo_envio = datos_envio.get('costo_envio', 0)
    total = subtotal + costo_envio
    
    # Generar orden de compra única
    buy_order = str(uuid.uuid4())[:26]  # Máximo 26 caracteres
    session_id = str(uuid.uuid4())
    
    # URL de retorno
    return_url = request.url_root.rstrip('/') + url_for('confirmar_pago_webpay')
    final_url = request.url_root.rstrip('/') + url_for('pago_finalizado')
    
    # Crear la transacción en Webpay
    try:
        headers = {
            'Tbk-Api-Key-Id': WEBPAY_COMMERCE_CODE,
            'Tbk-Api-Key-Secret': WEBPAY_API_KEY,
            'Content-Type': 'application/json'
        }
        
        # Validar que el monto sea válido (mínimo 1 CLP según documentación)
        if total < 1:
            return jsonify({'success': False, 'error': 'El monto mínimo de compra es $1 CLP'}), 400
        
        # Crear payload según documentación de Webpay Plus
        # https://www.transbankdevelopers.cl/documentacion/webpay-plus
        payload = {
            'buy_order': buy_order,  # Identificador único de la orden (máx 26 caracteres)
            'session_id': session_id,  # Identificador de sesión
            'amount': int(total),  # Monto en pesos chilenos (sin decimales)
            'return_url': return_url  # URL donde Webpay redirigirá después del pago
        }
        
        response = requests.post(
            f'{WEBPAY_URL}/rswebpaytransaction/api/webpay/v1.2/transactions',
            json=payload,
            headers=headers,
            timeout=30
        )
        
        print(f"Webpay Response Status: {response.status_code}")
        print(f"Webpay Response Headers: {response.headers}")
        print(f"Webpay Response Text: {response.text}")
        
        if response.status_code == 200 or response.status_code == 201:
            try:
                data = response.json()
                print(f"Webpay Response Data: {data}")
                
                token = data.get('token')
                url_webpay = data.get('url')
                
                if not token or not url_webpay:
                    error_msg = f'Error: La respuesta de Webpay no contiene token o URL. Respuesta: {data}'
                    print(error_msg)
                    return render_template('pago.html', error='Error al obtener la URL de pago de Webpay. Por favor, intenta nuevamente.')
                
                # Guardar información en la sesión
                session['webpay_token'] = token
                session['webpay_buy_order'] = buy_order
                session['webpay_amount'] = total
                session['metodo_pago'] = 'webpay'
                
                print(f"Redirigiendo a Webpay: {url_webpay}")
                print(f"Token Webpay: {token}")
                
                # Retornar JSON con la URL y el token
                # Webpay requiere que se envíe el token como parámetro POST
                return jsonify({
                    'success': True, 
                    'url': url_webpay,
                    'token': token
                })
            except ValueError as e:
                error_msg = f'Error al parsear respuesta JSON de Webpay: {str(e)}. Respuesta: {response.text}'
                print(error_msg)
                return render_template('pago.html', error='Error al procesar la respuesta de Webpay. Por favor, intenta nuevamente.')
        else:
            error_msg = f'Error en Webpay (Status {response.status_code}): {response.text}'
            print(error_msg)
            return jsonify({'success': False, 'error': f'Error al iniciar el pago (Código: {response.status_code})'}), 500
    
    except requests.exceptions.RequestException as e:
        error_msg = f'Error de conexión con Webpay: {str(e)}'
        print(error_msg)
        return jsonify({'success': False, 'error': 'Error de conexión con Webpay. Por favor, verifica tu conexión e intenta nuevamente.'}), 500
    except Exception as e:
        error_msg = f'Error inesperado en Webpay: {str(e)}'
        print(error_msg)
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Error al procesar el pago. Por favor, intenta nuevamente.'}), 500

@app.route('/confirmar_pago_webpay')
def confirmar_pago_webpay():
    
    token = request.args.get('token_ws')
    if not token:
        return redirect(url_for('pago_finalizado', estado='rechazado'))
    
    # Confirmar la transacción
    try:
        headers = {
            'Tbk-Api-Key-Id': WEBPAY_COMMERCE_CODE,
            'Tbk-Api-Key-Secret': WEBPAY_API_KEY,
            'Content-Type': 'application/json'
        }
        
        # Confirmar la transacción según documentación de Webpay Plus
        # https://www.transbankdevelopers.cl/documentacion/webpay-plus
        response = requests.put(
            f'{WEBPAY_URL}/rswebpaytransaction/api/webpay/v1.2/transactions/{token}',
            headers=headers,
            timeout=30
        )
        
        print(f"Webpay Confirm Response Status: {response.status_code}")
        print(f"Webpay Confirm Response: {response.text}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                status = data.get('status')
                
                print(f"Webpay Transaction Status: {status}")
                print(f"Webpay Transaction Data: {data}")
                
                if status == 'AUTHORIZED':
                    # Pago exitoso - procesar igual que Mercado Pago
                    return procesar_pago_exitoso('webpay', token, data)
                else:
                    # Pago rechazado o fallido
                    error_detail = data.get('response_code', 'Desconocido')
                    print(f"Pago rechazado. Código de respuesta: {error_detail}")
                    return redirect(url_for('pago_finalizado', estado='rechazado'))
            except ValueError as e:
                print(f"Error al parsear respuesta de confirmación: {str(e)}")
                return redirect(url_for('pago_finalizado', estado='error'))
        else:
            print(f"Error al confirmar transacción. Status: {response.status_code}, Response: {response.text}")
            return redirect(url_for('pago_finalizado', estado='error'))
    
    except Exception as e:
        print(f"Error al confirmar pago: {str(e)}")
        return redirect(url_for('pago_finalizado', estado='error'))

@app.route('/pago_finalizado')
def pago_finalizado():
    estado = request.args.get('estado', 'error')
    return render_template('pago.html', estado=estado)

@app.route('/pago', methods=['GET', 'POST'])
def pago():
    return render_template('pago.html')

@app.route('/admin/logout')
def admin_logout():
    username = session.get('admin_username', 'unknown')
    session.clear()
    security_logger.info(f"Logout exitoso: {username}")
    return redirect(url_for('index'))

@app.route('/api/productos')
def api_productos():
    categoria = request.args.get('categoria', 'nuevo').lower()
    conn = get_db_connection()
    
    # Filtrar productos por categoría (solo activos)
    if categoria == 'nuevo':
        productos = conn.execute('SELECT * FROM productos WHERE activo = 1 ORDER BY id DESC').fetchall()
    elif categoria == 'ropa':
        productos = conn.execute('''
            SELECT * FROM productos 
            WHERE activo = 1 
            AND categoria IS NOT NULL
            AND categoria = 'ropa'
            AND categoria != ''
            ORDER BY id DESC
        ''').fetchall()
    elif categoria == 'accesorios':
        productos = conn.execute('''
            SELECT * FROM productos 
            WHERE activo = 1 
            AND categoria IS NOT NULL
            AND categoria = 'accesorios'
            AND categoria != ''
            ORDER BY id DESC
        ''').fetchall()
    else:
        productos = conn.execute('SELECT * FROM productos WHERE activo = 1 ORDER BY id DESC').fetchall()
    
    conn.close()
    
    productos_list = []
    for producto in productos:
        productos_list.append({
            'id': producto['id'],
            'nombre': producto['nombre'],
            'descripcion': producto['descripcion'],
            'precio': producto['precio'],
            'imagen': producto['imagen'],
            'categoria': producto['categoria']
        })
    
    return jsonify({'success': True, 'productos': productos_list, 'total': len(productos_list)})

@app.route('/api/stock_tallas/<int:producto_id>')
def api_stock_tallas(producto_id):
    conn = get_db_connection()
    try:
        tallas = conn.execute('SELECT talla, stock FROM tallas WHERE producto_id = ?', (producto_id,)).fetchall()
        conn.close()
        
        tallas_dict = {t['talla']: t['stock'] for t in tallas}
        return jsonify({'success': True, 'stock': tallas_dict})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/buscar_productos')
def api_buscar_productos():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({'success': False, 'error': 'Término de búsqueda requerido'}), 400
    
    conn = get_db_connection()
    # Búsqueda en nombre y descripción (case-insensitive)
    productos = conn.execute('''
        SELECT * FROM productos 
        WHERE activo = 1 
        AND (nombre LIKE ? OR descripcion LIKE ?)
        ORDER BY id DESC
    ''', (f'%{query}%', f'%{query}%')).fetchall()
    conn.close()
    
    productos_list = []
    for producto in productos:
        productos_list.append({
            'id': producto['id'],
            'nombre': producto['nombre'],
            'descripcion': producto['descripcion'],
            'precio': producto['precio'],
            'imagen': producto['imagen'],
            'categoria': producto['categoria']
        })
    
    return jsonify({'success': True, 'productos': productos_list, 'total': len(productos_list)})

# Ruta para historial de pedidos (pública - sin registro)
@app.route('/mis_pedidos')
def mis_pedidos():
    return render_template('mis_pedidos.html')

@app.route('/api/buscar_pedido', methods=['POST'])
def api_buscar_pedido():
    data = request.get_json()
    numero_pedido = data.get('numero_pedido', '').strip()
    email = data.get('email', '').strip().lower()
    
    if not numero_pedido and not email:
        return jsonify({'success': False, 'error': 'Debes proporcionar número de pedido o email'}), 400
    
    conn = get_db_connection()
    
    # Buscar por número de pedido o email
    if numero_pedido:
        pedido = conn.execute('SELECT * FROM pedidos WHERE numero_pedido = ?', (numero_pedido,)).fetchone()
    else:
        pedido = conn.execute('SELECT * FROM pedidos WHERE usuario_email = ? ORDER BY fecha DESC LIMIT 1', (email,)).fetchone()
    
    if not pedido:
        conn.close()
        return jsonify({'success': False, 'error': 'Pedido no encontrado'}), 404
    
    # Obtener items del pedido
    items = conn.execute('SELECT * FROM pedido_items WHERE pedido_id = ?', (pedido['id'],)).fetchall()
    conn.close()
    
    pedido_dict = {
        'id': pedido['id'],
        'numero_pedido': pedido['numero_pedido'],
        'usuario_nombre': pedido['usuario_nombre'],
        'usuario_email': pedido['usuario_email'],
        'usuario_telefono': pedido['usuario_telefono'],
        'tipo_envio': pedido['tipo_envio'],
        'direccion': pedido['direccion'],
        'comuna': pedido['comuna'],
        'region': pedido['region'],
        'costo_envio': pedido['costo_envio'],
        'subtotal': pedido['subtotal'],
        'descuento': pedido['descuento'],
        'total': pedido['total'],
        'metodo_pago': pedido['metodo_pago'],
        'estado': pedido['estado'],
        'fecha': pedido['fecha'],
        'items': [dict(item) for item in items]
    }
    
    return jsonify({'success': True, 'pedido': pedido_dict})

# ==================== RUTAS DE ADMINISTRACIÓN ====================

# Verificar si es admin
def is_admin():
    if not session.get('admin_logged_in'):
        return False
    
    # Verificar timeout de sesión
    if 'last_activity' in session:
        try:
            last_activity = datetime.fromisoformat(session['last_activity'])
            if datetime.now() - last_activity > timedelta(hours=2):
                session.clear()
                return False
        except:
            return False
    
    # Actualizar última actividad
    session['last_activity'] = datetime.now().isoformat()
    return True

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@admin_required
def admin_index():
    
    conn = get_db_connection()
    
    # Estadísticas
    total_productos = conn.execute('SELECT COUNT(*) FROM productos').fetchone()[0]
    total_pedidos = conn.execute('SELECT COUNT(*) FROM pedidos').fetchone()[0]
    total_galeria = conn.execute('SELECT COUNT(*) FROM galeria').fetchone()[0]
    total_archivo = conn.execute('SELECT COUNT(*) FROM archivo').fetchone()[0]
    total_cupones = conn.execute('SELECT COUNT(*) FROM cupones').fetchone()[0]
    
    # Pedidos recientes
    pedidos_recientes = conn.execute('''
        SELECT * FROM pedidos ORDER BY fecha DESC LIMIT 5
    ''').fetchall()
    
    # Productos con stock bajo (menos de 10 unidades en total)
    productos_stock_bajo = conn.execute('''
        SELECT p.id, p.nombre, SUM(t.stock) as stock_total
        FROM productos p
        LEFT JOIN tallas t ON p.id = t.producto_id
        WHERE p.activo = 1
        GROUP BY p.id, p.nombre
        HAVING stock_total < 10 OR stock_total IS NULL
        ORDER BY stock_total ASC
        LIMIT 10
    ''').fetchall()
    
    # Obtener estado de las secciones
    config_secciones = conn.execute('SELECT seccion, habilitada, mensaje FROM configuracion_secciones').fetchall()
    config_dict = {c['seccion']: {'habilitada': bool(c['habilitada']), 'mensaje': c['mensaje']} for c in config_secciones}
    
    conn.close()
    
    return render_template('admin/index.html', 
                           total_productos=total_productos,
                           total_pedidos=total_pedidos,
                           total_galeria=total_galeria,
                           total_archivo=total_archivo,
                           total_cupones=total_cupones,
                           pedidos_recientes=pedidos_recientes,
                           productos_stock_bajo=productos_stock_bajo,
                           config_secciones=config_dict)

# ==================== GESTIÓN DE PRODUCTOS ====================

@app.route('/admin/productos')
def admin_productos():
    if not is_admin():
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    productos = conn.execute('SELECT * FROM productos ORDER BY id DESC').fetchall()
    conn.close()
    
    return render_template('admin/productos.html', productos=productos)

@app.route('/admin/productos/agregar', methods=['GET', 'POST'])
def admin_agregar_producto():
    if not is_admin():
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        descripcion = request.form.get('descripcion', '')
        precio = float(request.form.get('precio', 0))
        categoria = request.form.get('categoria', 'ropa')
        stock = int(request.form.get('stock', 0))
        
        # Manejar imagen
        imagen = '/static/img/prueba.galeria.png'  # Por defecto
        if 'imagen' in request.files:
            file = request.files['imagen']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Reemplazar espacios restantes con guiones bajos (secure_filename puede dejar algunos)
                filename = filename.replace(' ', '_')
                # Agregar timestamp para evitar conflictos
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                imagen = f'/static/img/{filename}'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insertar producto
        cursor.execute('''
            INSERT INTO productos (nombre, descripcion, precio, imagen, categoria, stock)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (nombre, descripcion, precio, imagen, categoria, stock))
        
        producto_id = cursor.lastrowid
        
        # Gestionar tallas
        tallas_data = request.form.getlist('tallas[]')
        stocks_data = request.form.getlist('stocks[]')
        
        # Si no se proporcionaron tallas, crear "Talla Única" con el stock del producto
        if not tallas_data or len(tallas_data) == 0:
            cursor.execute('''
                INSERT INTO tallas (producto_id, talla, stock)
                VALUES (?, ?, ?)
            ''', (producto_id, 'Talla Única', stock))
        else:
            # Insertar las tallas proporcionadas
            for i, talla in enumerate(tallas_data):
                if talla and talla.strip():
                    stock_talla = int(stocks_data[i]) if i < len(stocks_data) and stocks_data[i] else 0
                    cursor.execute('''
                        INSERT INTO tallas (producto_id, talla, stock)
                        VALUES (?, ?, ?)
                    ''', (producto_id, talla.strip(), stock_talla))
        
        conn.commit()
        conn.close()
        
        return redirect(url_for('admin_productos'))
    
    return render_template('admin/producto_form.html', producto=None, tallas=[])

@app.route('/admin/productos/editar/<int:id>', methods=['GET', 'POST'])
def admin_editar_producto(id):
    if not is_admin():
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        nombre = request.form.get('nombre')
        descripcion = request.form.get('descripcion', '')
        precio = float(request.form.get('precio', 0))
        categoria = request.form.get('categoria', 'ropa')
        stock = int(request.form.get('stock', 0))
        activo = 1 if request.form.get('activo') == 'on' else 0
        
        # Obtener imagen actual
        producto_actual = conn.execute('SELECT imagen FROM productos WHERE id = ?', (id,)).fetchone()
        imagen = producto_actual['imagen'] if producto_actual else '/static/img/prueba.galeria.png'
        
        # Manejar nueva imagen si se sube
        if 'imagen' in request.files:
            file = request.files['imagen']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Reemplazar espacios restantes con guiones bajos
                filename = filename.replace(' ', '_')
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                imagen = f'/static/img/{filename}'
        
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE productos 
            SET nombre = ?, descripcion = ?, precio = ?, imagen = ?, categoria = ?, stock = ?, activo = ?
            WHERE id = ?
        ''', (nombre, descripcion, precio, imagen, categoria, stock, activo, id))
        
        # Gestionar tallas
        tallas_data = request.form.getlist('tallas[]')
        stocks_data = request.form.getlist('stocks[]')
        tallas_ids = request.form.getlist('tallas_ids[]')
        
        # Eliminar tallas que ya no están
        if tallas_ids:
            placeholders = ','.join(['?'] * len(tallas_ids))
            cursor.execute(f'DELETE FROM tallas WHERE producto_id = ? AND id NOT IN ({placeholders})', (id, *tallas_ids))
        else:
            cursor.execute('DELETE FROM tallas WHERE producto_id = ?', (id,))
        
        # Actualizar o insertar tallas
        for i, talla in enumerate(tallas_data):
            if talla and talla.strip():
                stock_talla = int(stocks_data[i]) if i < len(stocks_data) and stocks_data[i] else 0
                talla_id = int(tallas_ids[i]) if i < len(tallas_ids) and tallas_ids[i] else None
                
                if talla_id:
                    # Actualizar talla existente
                    cursor.execute('''
                        UPDATE tallas SET talla = ?, stock = ?
                        WHERE id = ? AND producto_id = ?
                    ''', (talla.strip(), stock_talla, talla_id, id))
                else:
                    # Insertar nueva talla
                    cursor.execute('''
                        INSERT INTO tallas (producto_id, talla, stock)
                        VALUES (?, ?, ?)
                    ''', (id, talla.strip(), stock_talla))
        
        conn.commit()
        conn.close()
        
        return redirect(url_for('admin_productos'))
    
    producto = conn.execute('SELECT * FROM productos WHERE id = ?', (id,)).fetchone()
    
    # Obtener tallas del producto
    tallas = conn.execute('SELECT * FROM tallas WHERE producto_id = ? ORDER BY id', (id,)).fetchall()
    
    conn.close()
    
    if not producto:
        return redirect(url_for('admin_productos'))
    
    return render_template('admin/producto_form.html', producto=producto, tallas=tallas)

@app.route('/admin/productos/eliminar/<int:id>', methods=['POST'])
def admin_eliminar_producto(id):
    if not is_admin():
        return jsonify({'success': False, 'error': 'No autorizado'}), 401
    
    conn = get_db_connection()
    conn.execute('DELETE FROM productos WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# ==================== GESTIÓN DE GALERÍA ====================

@app.route('/admin/galeria')
def admin_galeria():
    if not is_admin():
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM galeria ORDER BY fecha DESC').fetchall()
    conn.close()
    
    return render_template('admin/galeria.html', items=items)

@app.route('/admin/galeria/agregar', methods=['GET', 'POST'])
def admin_agregar_galeria():
    if not is_admin():
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        titulo = request.form.get('titulo', '')
        descripcion = request.form.get('descripcion', '')
        modelo = request.form.get('modelo', '')
        coleccion = request.form.get('coleccion', '')
        
        # Manejar imagen
        imagen = '/static/img/prueba.galeria.png'
        if 'imagen' in request.files:
            file = request.files['imagen']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Reemplazar espacios restantes con guiones bajos
                filename = filename.replace(' ', '_')
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                imagen = f'/static/img/{filename}'
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO galeria (titulo, imagen, descripcion, modelo, coleccion)
            VALUES (?, ?, ?, ?, ?)
        ''', (titulo, imagen, descripcion, modelo, coleccion))
        conn.commit()
        conn.close()
        
        return redirect(url_for('admin_galeria'))
    
    return render_template('admin/galeria_form.html', item=None)

@app.route('/admin/galeria/editar/<int:id>', methods=['GET', 'POST'])
def admin_editar_galeria(id):
    if not is_admin():
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        titulo = request.form.get('titulo', '')
        descripcion = request.form.get('descripcion', '')
        modelo = request.form.get('modelo', '')
        coleccion = request.form.get('coleccion', '')
        
        # Obtener imagen actual
        item_actual = conn.execute('SELECT imagen FROM galeria WHERE id = ?', (id,)).fetchone()
        imagen = item_actual['imagen'] if item_actual else '/static/img/prueba.galeria.png'
        
        # Manejar nueva imagen
        if 'imagen' in request.files:
            file = request.files['imagen']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Reemplazar espacios restantes con guiones bajos
                filename = filename.replace(' ', '_')
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                imagen = f'/static/img/{filename}'
        
        conn.execute('''
            UPDATE galeria 
            SET titulo = ?, imagen = ?, descripcion = ?, modelo = ?, coleccion = ?
            WHERE id = ?
        ''', (titulo, imagen, descripcion, modelo, coleccion, id))
        conn.commit()
        conn.close()
        
        return redirect(url_for('admin_galeria'))
    
    item = conn.execute('SELECT * FROM galeria WHERE id = ?', (id,)).fetchone()
    conn.close()
    
    if not item:
        return redirect(url_for('admin_galeria'))
    
    return render_template('admin/galeria_form.html', item=item)

@app.route('/admin/galeria/eliminar/<int:id>', methods=['POST'])
def admin_eliminar_galeria(id):
    if not is_admin():
        return jsonify({'success': False, 'error': 'No autorizado'}), 401
    
    conn = get_db_connection()
    conn.execute('DELETE FROM galeria WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# ==================== GESTIÓN DE ARCHIVO ====================

@app.route('/admin/archivo')
def admin_archivo():
    if not is_admin():
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    items = conn.execute('SELECT * FROM archivo ORDER BY fecha DESC').fetchall()
    conn.close()
    
    return render_template('admin/archivo.html', items=items)

@app.route('/admin/archivo/agregar', methods=['GET', 'POST'])
def admin_agregar_archivo():
    if not is_admin():
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        titulo = request.form.get('titulo')
        descripcion = request.form.get('descripcion', '')
        coleccion = request.form.get('coleccion', '')
        
        # Manejar imagen
        imagen = '/static/img/prueba.galeria.png'
        if 'imagen' in request.files:
            file = request.files['imagen']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Reemplazar espacios restantes con guiones bajos
                filename = filename.replace(' ', '_')
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                imagen = f'/static/img/{filename}'
        
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO archivo (titulo, imagen, descripcion, coleccion)
            VALUES (?, ?, ?, ?)
        ''', (titulo, imagen, descripcion, coleccion))
        conn.commit()
        conn.close()
        
        return redirect(url_for('admin_archivo'))
    
    return render_template('admin/archivo_form.html', item=None)

@app.route('/admin/archivo/editar/<int:id>', methods=['GET', 'POST'])
def admin_editar_archivo(id):
    if not is_admin():
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        titulo = request.form.get('titulo')
        descripcion = request.form.get('descripcion', '')
        coleccion = request.form.get('coleccion', '')
        
        # Obtener imagen actual
        item_actual = conn.execute('SELECT imagen FROM archivo WHERE id = ?', (id,)).fetchone()
        imagen = item_actual['imagen'] if item_actual else '/static/img/prueba.galeria.png'
        
        # Manejar nueva imagen
        if 'imagen' in request.files:
            file = request.files['imagen']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Reemplazar espacios restantes con guiones bajos
                filename = filename.replace(' ', '_')
                filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                imagen = f'/static/img/{filename}'
        
        conn.execute('''
            UPDATE archivo 
            SET titulo = ?, imagen = ?, descripcion = ?, coleccion = ?
            WHERE id = ?
        ''', (titulo, imagen, descripcion, coleccion, id))
        conn.commit()
        conn.close()
        
        return redirect(url_for('admin_archivo'))
    
    item = conn.execute('SELECT * FROM archivo WHERE id = ?', (id,)).fetchone()
    conn.close()
    
    if not item:
        return redirect(url_for('admin_archivo'))
    
    return render_template('admin/archivo_form.html', item=item)

@app.route('/admin/archivo/eliminar/<int:id>', methods=['POST'])
def admin_eliminar_archivo(id):
    if not is_admin():
        return jsonify({'success': False, 'error': 'No autorizado'}), 401
    
    conn = get_db_connection()
    conn.execute('DELETE FROM archivo WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# ==================== GESTIÓN DE CUPONES ====================

@app.route('/admin/cupones')
def admin_cupones():
    if not is_admin():
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    cupones = conn.execute('SELECT * FROM cupones ORDER BY fecha_creacion DESC').fetchall()
    conn.close()
    
    return render_template('admin/cupones.html', cupones=cupones)

@app.route('/admin/cupones/agregar', methods=['GET', 'POST'])
def admin_agregar_cupon():
    if not is_admin():
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        codigo = request.form.get('codigo', '').strip().upper()
        tipo_descuento = request.form.get('tipo_descuento', 'porcentaje')
        valor_descuento = float(request.form.get('valor_descuento', 0))
        fecha_inicio = request.form.get('fecha_inicio') or None
        fecha_fin = request.form.get('fecha_fin') or None
        uso_maximo = int(request.form.get('uso_maximo', 0) or 0)
        monto_minimo = float(request.form.get('monto_minimo', 0) or 0)
        activo = 1 if request.form.get('activo') == 'on' else 0
        
        if not codigo:
            return render_template('admin/cupon_form.html', error='El código es requerido')
        
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO cupones (codigo, tipo_descuento, valor_descuento, fecha_inicio, fecha_fin, uso_maximo, monto_minimo, activo)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (codigo, tipo_descuento, valor_descuento, fecha_inicio, fecha_fin, uso_maximo, monto_minimo, activo))
            conn.commit()
            conn.close()
            return redirect(url_for('admin_cupones'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('admin/cupon_form.html', error='El código de cupón ya existe')
    
    return render_template('admin/cupon_form.html', cupon=None)

@app.route('/admin/cupones/editar/<int:id>', methods=['GET', 'POST'])
def admin_editar_cupon(id):
    if not is_admin():
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        codigo = request.form.get('codigo', '').strip().upper()
        tipo_descuento = request.form.get('tipo_descuento', 'porcentaje')
        valor_descuento = float(request.form.get('valor_descuento', 0))
        fecha_inicio = request.form.get('fecha_inicio') or None
        fecha_fin = request.form.get('fecha_fin') or None
        uso_maximo = int(request.form.get('uso_maximo', 0) or 0)
        monto_minimo = float(request.form.get('monto_minimo', 0) or 0)
        activo = 1 if request.form.get('activo') == 'on' else 0
        
        # Verificar que el código no esté en uso por otro cupón
        cupon_existente = conn.execute('SELECT codigo FROM cupones WHERE id = ?', (id,)).fetchone()
        otro_cupon = conn.execute('SELECT id FROM cupones WHERE codigo = ? AND id != ?', (codigo, id)).fetchone()
        
        if otro_cupon:
            cupon = conn.execute('SELECT * FROM cupones WHERE id = ?', (id,)).fetchone()
            conn.close()
            return render_template('admin/cupon_form.html', cupon=cupon, error='El código de cupón ya existe')
        
        conn.execute('''
            UPDATE cupones 
            SET codigo = ?, tipo_descuento = ?, valor_descuento = ?, fecha_inicio = ?, fecha_fin = ?, 
                uso_maximo = ?, monto_minimo = ?, activo = ?
            WHERE id = ?
        ''', (codigo, tipo_descuento, valor_descuento, fecha_inicio, fecha_fin, uso_maximo, monto_minimo, activo, id))
        conn.commit()
        conn.close()
        return redirect(url_for('admin_cupones'))
    
    cupon = conn.execute('SELECT * FROM cupones WHERE id = ?', (id,)).fetchone()
    conn.close()
    
    if not cupon:
        return redirect(url_for('admin_cupones'))
    
    return render_template('admin/cupon_form.html', cupon=cupon)

@app.route('/admin/cupones/eliminar/<int:id>', methods=['POST'])
def admin_eliminar_cupon(id):
    if not is_admin():
        return jsonify({'success': False, 'error': 'No autorizado'}), 401
    
    conn = get_db_connection()
    conn.execute('DELETE FROM cupones WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/validar_cupon', methods=['POST'])
def validar_cupon():
    if not request.is_json:
        return jsonify({'success': False, 'error': 'Content-Type debe ser application/json'}), 400
    
    data = request.get_json()
    codigo = data.get('codigo', '').strip().upper()
    subtotal = float(data.get('subtotal', 0))
    
    if not codigo:
        return jsonify({'success': False, 'error': 'Código de cupón requerido'}), 400
    
    conn = get_db_connection()
    cupon = conn.execute('SELECT * FROM cupones WHERE codigo = ?', (codigo,)).fetchone()
    
    if not cupon:
        conn.close()
        return jsonify({'success': False, 'error': 'Cupón no encontrado'}), 404
    
    # Validar que el cupón esté activo
    if not cupon['activo']:
        conn.close()
        return jsonify({'success': False, 'error': 'Cupón inactivo'}), 400
    
    # Validar fechas
    hoy = date.today()
    
    if cupon['fecha_inicio']:
        fecha_inicio = datetime.strptime(cupon['fecha_inicio'], '%Y-%m-%d').date()
        if hoy < fecha_inicio:
            conn.close()
            return jsonify({'success': False, 'error': 'El cupón aún no está vigente'}), 400
    
    if cupon['fecha_fin']:
        fecha_fin = datetime.strptime(cupon['fecha_fin'], '%Y-%m-%d').date()
        if hoy > fecha_fin:
            conn.close()
            return jsonify({'success': False, 'error': 'El cupón ha expirado'}), 400
    
    # Validar uso máximo
    if cupon['uso_maximo'] > 0 and cupon['usos_actuales'] >= cupon['uso_maximo']:
        conn.close()
        return jsonify({'success': False, 'error': 'Cupón agotado'}), 400
    
    # Validar monto mínimo
    if cupon['monto_minimo'] > 0 and subtotal < cupon['monto_minimo']:
        conn.close()
        return jsonify({'success': False, 'error': f'Monto mínimo requerido: ${cupon["monto_minimo"]:,.0f}'.replace(',', '.')}), 400
    
    # Calcular descuento
    if cupon['tipo_descuento'] == 'porcentaje':
        descuento = subtotal * (cupon['valor_descuento'] / 100)
        if descuento > subtotal:
            descuento = subtotal
    else:  # fijo
        descuento = cupon['valor_descuento']
        if descuento > subtotal:
            descuento = subtotal
    
    conn.close()
    
    # Guardar cupón en sesión
    session['cupon_aplicado'] = {
        'cupon_id': cupon['id'],
        'codigo': cupon['codigo'],
        'tipo_descuento': cupon['tipo_descuento'],
        'valor_descuento': cupon['valor_descuento'],
        'descuento': round(descuento, 2)
    }
    
    conn.close()
    
    return jsonify({
        'success': True,
        'cupon_id': cupon['id'],
        'codigo': cupon['codigo'],
        'tipo_descuento': cupon['tipo_descuento'],
        'valor_descuento': cupon['valor_descuento'],
        'descuento': round(descuento, 2)
    })

@app.route('/api/remover_cupon', methods=['POST'])
def remover_cupon():
    session.pop('cupon_aplicado', None)
    return jsonify({'success': True})

# ==================== GESTIÓN DE CONFIGURACIÓN DE SECCIONES ====================

@app.route('/admin/configuracion')
def admin_configuracion():
    if not is_admin():
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    secciones = conn.execute('SELECT * FROM configuracion_secciones ORDER BY seccion').fetchall()
    conn.close()
    
    return render_template('admin/configuracion.html', secciones=secciones)

@app.route('/admin/configuracion/actualizar', methods=['POST'])
def admin_actualizar_configuracion():
    if not is_admin():
        return jsonify({'success': False, 'error': 'No autorizado'}), 401
    
    data = request.get_json()
    seccion = data.get('seccion')
    habilitada = data.get('habilitada', 1)
    mensaje = data.get('mensaje', 'SECCIÓN CERRADA')
    
    if not seccion:
        return jsonify({'success': False, 'error': 'Sección requerida'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Actualizar o insertar configuración
    cursor.execute('''
        INSERT INTO configuracion_secciones (seccion, habilitada, mensaje)
        VALUES (?, ?, ?)
        ON CONFLICT(seccion) DO UPDATE SET
            habilitada = ?,
            mensaje = ?,
            fecha_actualizacion = CURRENT_TIMESTAMP
    ''', (seccion, habilitada, mensaje, habilitada, mensaje))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# Función helper para verificar si una sección está habilitada
def seccion_habilitada(seccion):
    """Verifica si una sección está habilitada"""
    conn = get_db_connection()
    config = conn.execute('''
        SELECT habilitada FROM configuracion_secciones WHERE seccion = ?
    ''', (seccion,)).fetchone()
    conn.close()
    
    # Si no existe configuración, asumir que está habilitada
    if not config:
        return True
    
    return bool(config['habilitada'])

def obtener_mensaje_seccion(seccion):
    """Obtiene el mensaje de una sección cerrada"""
    conn = get_db_connection()
    config = conn.execute('''
        SELECT mensaje FROM configuracion_secciones WHERE seccion = ?
    ''', (seccion,)).fetchone()
    conn.close()
    
    if not config:
        return 'SECCIÓN CERRADA'
    
    return config['mensaje'] or 'SECCIÓN CERRADA'

# ==================== GESTIÓN DE PEDIDOS ====================

@app.route('/admin/pedidos')
def admin_pedidos():
    if not is_admin():
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    pedidos = conn.execute('''
        SELECT * FROM pedidos ORDER BY fecha DESC
    ''').fetchall()
    
    # Obtener items de cada pedido
    pedidos_con_items = []
    for pedido in pedidos:
        pedido_items = conn.execute('''
            SELECT * FROM pedido_items WHERE pedido_id = ?
        ''', (pedido['id'],)).fetchall()
        pedidos_con_items.append({
            'pedido': pedido,
            'pedido_items': pedido_items  # Cambiar nombre para evitar conflicto con items()
        })
    
    conn.close()
    
    return render_template('admin/pedidos.html', pedidos=pedidos_con_items)

# Ruta para exportar pedidos a CSV
@app.route('/admin/pedidos/exportar')
@admin_required
def admin_exportar_pedidos():
    import csv
    from io import StringIO
    
    formato = request.args.get('formato', 'csv').lower()
    fecha_inicio = request.args.get('fecha_inicio', '')
    fecha_fin = request.args.get('fecha_fin', '')
    
    conn = get_db_connection()
    
    # Construir consulta con filtros opcionales
    query = 'SELECT * FROM pedidos WHERE 1=1'
    params = []
    
    if fecha_inicio:
        query += ' AND fecha >= ?'
        params.append(fecha_inicio)
    if fecha_fin:
        query += ' AND fecha <= ?'
        params.append(fecha_fin)
    
    query += ' ORDER BY fecha DESC'
    
    pedidos = conn.execute(query, params).fetchall()
    
    if formato == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        
        # Encabezados
        writer.writerow([
            'ID', 'Número de Pedido', 'Cliente', 'Email', 'Teléfono',
            'Tipo de Envío', 'Dirección', 'Comuna', 'Región',
            'Costo de Envío', 'Subtotal', 'Descuento', 'Total',
            'Método de Pago', 'Estado', 'Fecha'
        ])
        
        # Datos
        for pedido in pedidos:
            writer.writerow([
                pedido['id'],
                pedido['numero_pedido'] or '',
                pedido['usuario_nombre'] or '',
                pedido['usuario_email'] or '',
                pedido['usuario_telefono'] or '',
                pedido['tipo_envio'] or '',
                pedido['direccion'] or '',
                pedido['comuna'] or '',
                pedido['region'] or '',
                pedido['costo_envio'] or 0,
                pedido['subtotal'] or 0,
                pedido['descuento'] or 0,
                pedido['total'] or 0,
                pedido['metodo_pago'] or '',
                pedido['estado'] or '',
                pedido['fecha'] or ''
            ])
        
        conn.close()
        
        # Crear respuesta
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename=pedidos_{datetime.now().strftime("%Y%m%d")}.csv'
        return response
    
    conn.close()
    return redirect(url_for('admin_pedidos'))

@app.route('/admin/pedidos/<int:id>')
def admin_detalle_pedido(id):
    if not is_admin():
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    pedido = conn.execute('SELECT * FROM pedidos WHERE id = ?', (id,)).fetchone()
    items = conn.execute('SELECT * FROM pedido_items WHERE pedido_id = ?', (id,)).fetchall()
    conn.close()
    
    if not pedido:
        return redirect(url_for('admin_pedidos'))
    
    return render_template('admin/detalle_pedido.html', pedido=pedido, items=items)

@app.route('/admin/pedidos/<int:id>/estado', methods=['POST'])
def admin_cambiar_estado_pedido(id):
    if not is_admin():
        return jsonify({'success': False, 'error': 'No autorizado'}), 401
    
    nuevo_estado = request.json.get('estado')
    
    conn = get_db_connection()
    conn.execute('UPDATE pedidos SET estado = ? WHERE id = ?', (nuevo_estado, id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# Función para enviar boleta por correo
def enviar_boleta_correo(pedido, items, carrito):
    """Envía la boleta del pedido por correo electrónico"""
    try:
        msg = Message(
            subject=f'Boleta de Compra VENT - Pedido {pedido["numero_pedido"]}',
            recipients=[pedido['usuario_email']],
            html=render_template('email/boleta.html', pedido=pedido, items=items, carrito=carrito)
        )
        mail.send(msg)
        print(f"Correo enviado a {pedido['usuario_email']}")
    except Exception as e:
        print(f"Error al enviar correo: {str(e)}")

# Handler para errores 404
@app.errorhandler(404)
def pagina_no_encontrada(error):
    return render_template('404.html'), 404

# Handler para errores 500
@app.errorhandler(500)
def error_interno(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Crear las tablas si no existen
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
