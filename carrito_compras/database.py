import os
import sqlite3

# Base de datos persistente (Postgres en Neon/Vercel; SQLite en local). si existe POSTGRES_URL (o DATABASE_URL) usamos PostgreSQL.
# Si no, usamos SQLite (local = database.db; en Vercel sin Postgres = /tmp, no persiste).
_raw = (os.environ.get('POSTGRES_URL') or os.environ.get('DATABASE_URL') or '').strip()
# Por si pegaron "psql postgresql://..." en la variable, usar solo la URL
if _raw.lower().startswith('psql '):
    _raw = _raw[5:].strip()
POSTGRES_URL = _raw if _raw.startswith('postgresql://') or _raw.startswith('postgres://') else None

if POSTGRES_URL:
    import psycopg2
    from psycopg2.extras import RealDictCursor

    class _RowWrapper:
        """Permite row[0] y row['col'] como en sqlite3.Row."""
        def __init__(self, d):
            self._d = d or {}
            self._vals = list(self._d.values()) if self._d else []
        def __getitem__(self, k):
            if isinstance(k, int):
                return self._vals[k] if k < len(self._vals) else None
            return self._d.get(k)
        def __getattr__(self, name):
            return self._d.get(name)
        def keys(self):
            return self._d.keys()

    class _CursorWrapper:
        """Convierte ? en %s y devuelve filas con acceso por índice y nombre."""
        def __init__(self, cursor):
            self._cur = cursor
        def execute(self, sql, params=None):
            if params is not None and '?' in sql:
                sql = sql.replace('?', '%s')
            if params is not None:
                return self._cur.execute(sql, params)
            return self._cur.execute(sql)
        def fetchone(self):
            r = self._cur.fetchone()
            return _RowWrapper(r) if r is not None else None
        def fetchall(self):
            return [_RowWrapper(r) for r in self._cur.fetchall()]
        def __getattr__(self, name):
            return getattr(self._cur, name)

    class _ConnWrapper:
        def __init__(self, conn):
            self._conn = conn
        def cursor(self):
            return _CursorWrapper(self._conn.cursor(cursor_factory=RealDictCursor))
        def execute(self, sql, params=None):
            """Para compatibilidad con código que usa conn.execute().fetchone()"""
            cur = self.cursor()
            cur.execute(sql, params)
            return cur
        def commit(self):
            return self._conn.commit()
        def close(self):
            return self._conn.close()

    def get_db_connection():
        return _ConnWrapper(psycopg2.connect(POSTGRES_URL))

    def _pg_alter_ignore(conn, sql):
        try:
            conn.cursor()._cur.execute(sql)
            conn.commit()
        except Exception:
            pass

    def init_db():
        conn = psycopg2.connect(POSTGRES_URL)
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS productos (
                id SERIAL PRIMARY KEY,
                nombre TEXT NOT NULL,
                descripcion TEXT,
                precio REAL NOT NULL,
                imagen TEXT,
                categoria TEXT,
                stock INTEGER DEFAULT 0,
                activo INTEGER DEFAULT 1
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS tallas (
                id SERIAL PRIMARY KEY,
                producto_id INTEGER,
                talla TEXT NOT NULL,
                stock INTEGER DEFAULT 0
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS pedidos (
                id SERIAL PRIMARY KEY,
                numero_pedido TEXT UNIQUE,
                usuario_email TEXT,
                usuario_nombre TEXT,
                usuario_telefono TEXT,
                tipo_envio TEXT,
                direccion TEXT,
                depto_casa TEXT,
                comuna TEXT,
                region TEXT,
                costo_envio REAL DEFAULT 0,
                subtotal REAL NOT NULL,
                total REAL NOT NULL,
                metodo_pago TEXT,
                estado TEXT DEFAULT 'pendiente',
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                datos_pago TEXT,
                cupon_id INTEGER,
                codigo_cupon TEXT,
                descuento REAL DEFAULT 0
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS pedido_items (
                id SERIAL PRIMARY KEY,
                pedido_id INTEGER,
                producto_id INTEGER,
                producto_nombre TEXT,
                talla TEXT,
                cantidad INTEGER,
                precio REAL
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS galeria (
                id SERIAL PRIMARY KEY,
                titulo TEXT,
                imagen TEXT NOT NULL,
                descripcion TEXT,
                modelo TEXT,
                coleccion TEXT,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS archivo (
                id SERIAL PRIMARY KEY,
                titulo TEXT NOT NULL,
                imagen TEXT,
                descripcion TEXT,
                coleccion TEXT,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS cupones (
                id SERIAL PRIMARY KEY,
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
        cur.execute('''
            CREATE TABLE IF NOT EXISTS usuarios_admin (
                id SERIAL PRIMARY KEY,
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
        cur.execute('''
            CREATE TABLE IF NOT EXISTS intentos_login (
                id SERIAL PRIMARY KEY,
                ip_address TEXT NOT NULL,
                usuario TEXT,
                exitoso INTEGER DEFAULT 0,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS configuracion_secciones (
                id SERIAL PRIMARY KEY,
                seccion TEXT UNIQUE NOT NULL,
                habilitada INTEGER DEFAULT 1,
                mensaje TEXT,
                fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS clientes (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                nombre TEXT NOT NULL,
                telefono TEXT,
                direccion TEXT,
                comuna TEXT,
                region TEXT,
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        try:
            cur.execute('ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS depto_casa TEXT')
            conn.commit()
        except Exception:
            pass
        cur.execute('''
            INSERT INTO configuracion_secciones (seccion, habilitada, mensaje)
            VALUES ('tienda', 1, 'TIENDA CERRADA'),
                   ('galeria', 1, 'GALERÍA CERRADA'),
                   ('archivo', 1, 'ARCHIVO CERRADO'),
                   ('nosotros', 1, 'SECCIÓN CERRADA'),
                   ('contacto', 1, 'SECCIÓN CERRADA')
            ON CONFLICT (seccion) DO NOTHING
        ''')
        cur.execute('SELECT COUNT(*) FROM productos')
        count = cur.fetchone()[0]
        if count == 0:
            cur.execute('''
                INSERT INTO productos (nombre, descripcion, precio, imagen, categoria)
                VALUES ('Camiseta Vent', 'Camiseta de algodón de alta calidad con logo Vent.', 19.99, '/static/img/prueba.galeria.png', 'ropa'),
                       ('Gorro Vent', 'Gorro de lana con bordado del logo Vent.', 24.99, '/static/img/prueba.galeria.png', 'accesorios'),
                       ('Sudadera Vent', 'Sudadera oversize de algodón orgánico.', 49.99, '/static/img/prueba.galeria.png', 'ropa')
            ''')
        conn.commit()
        cur.close()
        conn.close()

else:
    # SQLite (local o Vercel sin Postgres; en Vercel /tmp no persiste)
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
            cursor.execute('ALTER TABLE pedidos ADD COLUMN depto_casa TEXT')
        except sqlite3.OperationalError:
            pass
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
        try:
            cursor.execute('ALTER TABLE pedido_items ADD COLUMN talla TEXT')
        except sqlite3.OperationalError:
            pass
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
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intentos_login (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                usuario TEXT,
                exitoso INTEGER DEFAULT 0,
                fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS configuracion_secciones (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seccion TEXT UNIQUE NOT NULL,
                habilitada INTEGER DEFAULT 1,
                mensaje TEXT,
                fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clientes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                nombre TEXT NOT NULL,
                telefono TEXT,
                direccion TEXT,
                comuna TEXT,
                region TEXT,
                fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        for seccion, habilitada, mensaje in [
            ('tienda', 1, 'TIENDA CERRADA'), ('galeria', 1, 'GALERÍA CERRADA'),
            ('archivo', 1, 'ARCHIVO CERRADO'), ('nosotros', 1, 'SECCIÓN CERRADA'), ('contacto', 1, 'SECCIÓN CERRADA')
        ]:
            cursor.execute('INSERT OR IGNORE INTO configuracion_secciones (seccion, habilitada, mensaje) VALUES (?, ?, ?)', (seccion, habilitada, mensaje))
        cursor.execute('SELECT COUNT(*) FROM productos')
        count = cursor.fetchone()[0]
        if count == 0:
            for nombre, desc, precio, img, cat in [
                ("Camiseta Vent", "Camiseta de algodón de alta calidad con logo Vent.", 19.99, "/static/img/prueba.galeria.png", "ropa"),
                ("Gorro Vent", "Gorro de lana con bordado del logo Vent.", 24.99, "/static/img/prueba.galeria.png", "accesorios"),
                ("Sudadera Vent", "Sudadera oversize de algodón orgánico.", 49.99, "/static/img/prueba.galeria.png", "ropa"),
            ]:
                cursor.execute('INSERT INTO productos (nombre, descripcion, precio, imagen, categoria) VALUES (?, ?, ?, ?, ?)', (nombre, desc, precio, img, cat))
        conn.commit()
        conn.close()

if __name__ == '__main__':
    init_db()
