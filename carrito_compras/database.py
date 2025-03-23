import sqlite3

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Crear tabla de productos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS productos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            descripcion TEXT,
            precio REAL NOT NULL,
            imagen TEXT
        )
    ''')

    # Crear tabla de tallas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tallas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            producto_id INTEGER,
            talla TEXT NOT NULL,
            FOREIGN KEY (producto_id) REFERENCES productos (id)
        )
    ''')

    # Insertar datos de ejemplo (opcional)
    cursor.execute('''
        INSERT INTO productos (nombre, descripcion, precio, imagen)
        VALUES ("Camiseta", "Camiseta de algodón", 19.99, "img/camiseta.jpg")
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()