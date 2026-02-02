#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script para crear el usuario administrador inicial
Ejecutar: python create_admin_user.py
"""
import bcrypt
import getpass
import sqlite3
from database import get_db_connection

def create_admin_user():
    """Crea un usuario administrador"""
    print("=== Crear Usuario Administrador ===")
    
    usuario = input("Usuario: ").strip()
    if not usuario:
        print("Error: El usuario no puede estar vacío")
        return
    
    # Validar formato de usuario
    import re
    if not re.match(r'^[a-zA-Z0-9_]+$', usuario):
        print("Error: El usuario solo puede contener letras, números y guiones bajos")
        return
    
    password = getpass.getpass("Contraseña: ")
    if len(password) < 8:
        print("Error: La contraseña debe tener al menos 8 caracteres")
        return
    
    password_confirm = getpass.getpass("Confirmar contraseña: ")
    if password != password_confirm:
        print("Error: Las contraseñas no coinciden")
        return
    
    email = input("Email (opcional): ").strip()
    
    # Generar hash de contraseña
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Insertar en la base de datos
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO usuarios_admin (usuario, password_hash, email, activo)
            VALUES (?, ?, ?, 1)
        ''', (usuario, password_hash, email if email else None))
        conn.commit()
        print(f"\n✓ Usuario '{usuario}' creado exitosamente")
    except sqlite3.IntegrityError:
        print(f"\n✗ Error: El usuario '{usuario}' ya existe")
    except Exception as e:
        print(f"\n✗ Error al crear usuario: {str(e)}")
    finally:
        conn.close()

if __name__ == '__main__':
    create_admin_user()
