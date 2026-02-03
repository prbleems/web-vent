import sqlite3
import os

# En Vercel el sistema de archivos es de solo lectura excepto /tmp
# Usar /tmp para que la app arranque; los datos no persisten entre despliegues
DATABASE = os.environ.get('DATABASE_PATH') or (
    '/tmp/database.db' if os.environ.get('VERCEL') else 'database.db'
)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS productos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            descripcion TEXT,
            precio REAL NOT NULL,
            imagen TEXT,
            categoria TEXT,
            stock INTEGER DEFAULT 0,
            activo INTEGER DEFAULT 1
        )
    ''')
    
    try:
        cursor.execute('ALTER TABLE productos ADD COLUMN categoria TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE productos ADD COLUMN stock INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE productos ADD COLUMN activo INTEGER DEFAULT 1')
    except sqlite3.OperationalError:
        pass

    # Crear tabla de tallas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tallas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            producto_id INTEGER,
            talla TEXT NOT NULL,
            stock INTEGER DEFAULT 0,
            FOREIGN KEY (producto_id) REFERENCES productos (id)
        )
    ''')
    
    try:
        cursor.execute('ALTER TABLE tallas ADD COLUMN stock INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pedidos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            numero_pedido TEXT UNIQUE,
            usuario_email TEXT,
            usuario_nombre TEXT,
            usuario_telefono TEXT,
            tipo_envio TEXT,
            direccion TEXT,
            comuna TEXT,
            region TEXT,
            costo_envio REAL DEFAULT 0,
            subtotal REAL NOT NULL,
            total REAL NOT NULL,
            metodo_pago TEXT,
            estado TEXT DEFAULT 'pendiente',
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            datos_pago TEXT
        )
    ''')
    
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN numero_pedido TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN usuario_telefono TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN tipo_envio TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN direccion TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN comuna TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN region TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN costo_envio REAL DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN subtotal REAL')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN metodo_pago TEXT')
    except sqlite3.OperationalError:
        pass
    
    # Crear tabla de items de pedido
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS pedido_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pedido_id INTEGER,
            producto_id INTEGER,
            producto_nombre TEXT,
            talla TEXT,
            cantidad INTEGER,
            precio REAL,
            FOREIGN KEY (pedido_id) REFERENCES pedidos (id)
        )
    ''')
    
    # Agregar columna talla si no existe
    try:
        cursor.execute('ALTER TABLE pedido_items ADD COLUMN talla TEXT')
    except sqlite3.OperationalError:
        pass
    
    # Crear tabla de galería
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS galeria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT,
            imagen TEXT NOT NULL,
            descripcion TEXT,
            modelo TEXT,
            coleccion TEXT,
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Crear tabla de archivo
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS archivo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            imagen TEXT,
            descripcion TEXT,
            coleccion TEXT,
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Crear tabla de cupones
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cupones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo TEXT UNIQUE NOT NULL,
            tipo_descuento TEXT NOT NULL,
            valor_descuento REAL NOT NULL,
            fecha_inicio DATE,
            fecha_fin DATE,
            uso_maximo INTEGER DEFAULT 0,
            usos_actuales INTEGER DEFAULT 0,
            monto_minimo REAL DEFAULT 0,
            activo INTEGER DEFAULT 1,
            fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Agregar columnas de cupón a pedidos si no existen
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN cupon_id INTEGER')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN codigo_cupon TEXT')
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute('ALTER TABLE pedidos ADD COLUMN descuento REAL DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    
    # Crear tabla de usuarios administradores
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios_admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            activo INTEGER DEFAULT 1,
            ultimo_acceso TIMESTAMP,
            intentos_fallidos INTEGER DEFAULT 0,
            bloqueado_hasta TIMESTAMP,
            fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Crear tabla de intentos de login (para logging y rate limiting)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS intentos_login (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            usuario TEXT,
            exitoso INTEGER DEFAULT 0,
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Crear tabla de configuración de secciones
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS configuracion_secciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seccion TEXT UNIQUE NOT NULL,
            habilitada INTEGER DEFAULT 1,
            mensaje TEXT,
            fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insertar configuraciones por defecto si no existen
    secciones_default = [
        ('tienda', 1, 'TIENDA CERRADA'),
        ('galeria', 1, 'GALERÍA CERRADA'),
        ('archivo', 1, 'ARCHIVO CERRADO'),
        ('nosotros', 1, 'SECCIÓN CERRADA'),
        ('contacto', 1, 'SECCIÓN CERRADA')
    ]
    
    for seccion, habilitada, mensaje in secciones_default:
        cursor.execute('''
            INSERT OR IGNORE INTO configuracion_secciones (seccion, habilitada, mensaje)
            VALUES (?, ?, ?)
        ''', (seccion, habilitada, mensaje))

    # Verificar si ya hay productos antes de insertar datos de ejemplo
    cursor.execute('SELECT COUNT(*) FROM productos')
    count = cursor.fetchone()[0]
    
    # Insertar datos de ejemplo solo si la tabla está vacía
    if count == 0:
        cursor.execute('''
            INSERT INTO productos (nombre, descripcion, precio, imagen, categoria)
            VALUES ("Camiseta Vent", "Camiseta de algodón de alta calidad con logo Vent.", 19.99, "/static/img/prueba.galeria.png", "ropa")
        ''')
        cursor.execute('''
            INSERT INTO productos (nombre, descripcion, precio, imagen, categoria)
            VALUES ("Gorro Vent", "Gorro de lana con bordado del logo Vent.", 24.99, "/static/img/prueba.galeria.png", "accesorios")
        ''')
        cursor.execute('''
            INSERT INTO productos (nombre, descripcion, precio, imagen, categoria)
            VALUES ("Sudadera Vent", "Sudadera oversize de algodón orgánico.", 49.99, "/static/img/prueba.galeria.png", "ropa")
        ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()