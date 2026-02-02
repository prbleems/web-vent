// Funcionalidad para agregar productos al carrito desde la tienda

document.addEventListener('DOMContentLoaded', function() {
    // Agregar event listeners a todos los botones de agregar al carrito
    const botonesAgregar = document.querySelectorAll('.btn-agregar-carrito');
    
    botonesAgregar.forEach(boton => {
        boton.addEventListener('click', function(e) {
            e.preventDefault();
            
            const productoId = this.getAttribute('data-producto-id');
            const productoNombre = this.getAttribute('data-producto-nombre');
            const productoPrecio = parseFloat(this.getAttribute('data-producto-precio'));
            const productoImagen = this.getAttribute('data-producto-imagen');
            
            // Agregar producto al carrito
            agregarAlCarrito(productoId, productoNombre, productoPrecio, productoImagen);
        });
    });
});

function agregarAlCarrito(productoId, nombre, precio, imagen) {
    // Validar datos antes de enviar
    if (!productoId || !nombre || !precio) {
        console.error('Datos incompletos:', { productoId, nombre, precio, imagen });
        if (typeof notificarError === 'function') {
            notificarError('Error: Datos del producto incompletos');
        } else {
            alert('Error: Datos del producto incompletos');
        }
        return;
    }
    
    const datosEnvio = {
        producto_id: parseInt(productoId),
        nombre: nombre,
        precio: parseFloat(precio),
        imagen: imagen || '/static/img/prueba.galeria.png',
        talla: 'Talla Única', // Talla por defecto, se puede obtener del modal si existe
        cantidad: 1
    };
    
    console.log('Enviando al carrito:', datosEnvio);
    
    fetch('/agregar_carrito', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(datosEnvio)
    })
    .then(response => {
        console.log('Respuesta recibida:', response.status, response.statusText);
        if (!response.ok) {
            return response.json().then(err => {
                console.error('Error del servidor:', err);
                throw new Error(err.error || 'Error en la respuesta del servidor');
            });
        }
        return response.json();
    })
    .then(data => {
        console.log('Datos recibidos:', data);
        if (data.success) {
            // Guardar carrito en localStorage
            if (typeof guardarCarritoLocalStorage === 'function' && data.carrito) {
                guardarCarritoLocalStorage(data.carrito);
            }
            
            // Actualizar el badge del carrito
            actualizarBadgeCarrito(data.cantidad_total);
            
            // Mostrar feedback visual
            mostrarFeedbackAgregado();
            
            // Cerrar el modal si está abierto
            const modales = document.querySelectorAll('.modal');
            modales.forEach(modal => {
                const bootstrapModal = bootstrap.Modal.getInstance(modal);
                if (bootstrapModal) {
                    bootstrapModal.hide();
                }
            });
        } else {
            if (typeof notificarError === 'function') {
                notificarError('Error al agregar el producto al carrito: ' + (data.error || 'Error desconocido'));
            } else {
                alert('Error al agregar el producto al carrito: ' + (data.error || 'Error desconocido'));
            }
        }
    })
    .catch(error => {
        console.error('Error:', error);
        if (typeof notificarError === 'function') {
            notificarError('Error al agregar el producto al carrito: ' + error.message);
        } else {
            alert('Error al agregar el producto al carrito: ' + error.message);
        }
    });
}

function actualizarBadgeCarrito(cantidadTotal) {
    // Buscar el badge en el icono del carrito de la navegación
    const carritoIcon = document.querySelector('.vent-cart-icon');
    let badge = carritoIcon ? carritoIcon.querySelector('span') : null;
    
    if (cantidadTotal > 0) {
        if (!badge && carritoIcon) {
            // Crear el badge si no existe
            badge = document.createElement('span');
            badge.style.cssText = 'position: absolute; top: -8px; right: -8px; background: #000; color: #fff; border-radius: 50%; width: 18px; height: 18px; display: flex; align-items: center; justify-content: center; font-size: 10px; font-family: "Courier New", monospace;';
            carritoIcon.style.position = 'relative';
            carritoIcon.appendChild(badge);
        }
        if (badge) {
            badge.textContent = cantidadTotal;
            badge.style.display = 'flex';
        }
    } else {
        if (badge) {
            badge.style.display = 'none';
        }
    }
    
    // También recargar la página para actualizar el badge del servidor
    // O mejor, solo actualizar el badge sin recargar
}

function mostrarFeedbackAgregado() {
    // Usar el sistema de notificaciones si está disponible
    if (typeof notificarExito === 'function') {
        notificarExito('Producto agregado al carrito');
    } else {
        // Fallback a notificación básica
        const notificacion = document.createElement('div');
        notificacion.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background-color: #000;
            color: #fff;
            padding: 15px 25px;
            border-radius: 4px;
            font-family: "Courier New", Courier, monospace;
            font-size: 14px;
            z-index: 10000;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
            animation: slideIn 0.3s ease-out;
        `;
        notificacion.textContent = '✓ Producto agregado al carrito';
        document.body.appendChild(notificacion);
        
        // Remover después de 2 segundos
        setTimeout(() => {
            notificacion.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => {
                if (notificacion.parentNode) {
                    document.body.removeChild(notificacion);
                }
            }, 300);
        }, 2000);
    }
}

// Agregar estilos de animación si no existen
if (!document.getElementById('tienda-animations')) {
    const style = document.createElement('style');
    style.id = 'tienda-animations';
    style.textContent = `
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        @keyframes slideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(100%);
                opacity: 0;
            }
        }
    `;
    document.head.appendChild(style);
}
