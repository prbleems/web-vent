// Funciones para persistencia del carrito usando localStorage

const CARRITO_STORAGE_KEY = 'vent_carrito';

/**
 * Guarda el carrito en localStorage
 */
function guardarCarritoLocalStorage(carrito) {
    try {
        localStorage.setItem(CARRITO_STORAGE_KEY, JSON.stringify(carrito));
        console.log('Carrito guardado en localStorage');
    } catch (error) {
        console.error('Error al guardar carrito en localStorage:', error);
    }
}

/**
 * Carga el carrito desde localStorage
 */
function cargarCarritoLocalStorage() {
    try {
        const carritoStr = localStorage.getItem(CARRITO_STORAGE_KEY);
        if (carritoStr) {
            const carrito = JSON.parse(carritoStr);
            console.log('Carrito cargado desde localStorage:', carrito);
            return carrito;
        }
    } catch (error) {
        console.error('Error al cargar carrito desde localStorage:', error);
    }
    return [];
}

/**
 * Sincroniza el carrito del servidor con localStorage
 */
function sincronizarCarritoConServidor() {
    const carritoLocal = cargarCarritoLocalStorage();
    
    if (carritoLocal && carritoLocal.length > 0) {
        // Enviar cada producto del carrito local al servidor
        carritoLocal.forEach((item, index) => {
            // Validar que el item tenga los datos necesarios
            if (!item.id || !item.nombre || !item.precio) {
                console.warn('Item del carrito incompleto, omitiendo:', item);
                return;
            }
            
            // Agregar un pequeño delay entre requests para evitar sobrecarga
            setTimeout(() => {
                fetch('/agregar_carrito', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        producto_id: parseInt(item.id),
                        nombre: item.nombre,
                        precio: parseFloat(item.precio),
                        imagen: item.imagen || '/static/img/prueba.galeria.png',
                        talla: item.talla || 'Talla Única',
                        cantidad: parseInt(item.cantidad || 1)
                    })
                })
                .then(response => {
                    if (!response.ok) {
                        return response.json().then(err => {
                            // Si el error es por talla no disponible o stock, remover del localStorage
                            if (err.error && (err.error.includes('talla') || err.error.includes('stock') || err.error.includes('no está disponible'))) {
                                console.warn(`Producto removido del carrito local: ${err.error}`, item);
                                // Remover el item del localStorage
                                const carritoActualizado = cargarCarritoLocalStorage().filter(i => 
                                    !(i.id === item.id && i.talla === item.talla)
                                );
                                guardarCarritoLocalStorage(carritoActualizado);
                            }
                            throw new Error(err.error || `Error ${response.status}`);
                        });
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.success) {
                        console.log('Producto sincronizado:', item.nombre);
                    } else {
                        console.warn('Error al sincronizar producto:', data.error || 'Error desconocido');
                    }
                })
                .catch(error => {
                    // Solo mostrar error si no es un error de validación esperado
                    if (!error.message || (!error.message.includes('talla') && !error.message.includes('stock'))) {
                        console.error('Error al sincronizar producto:', error.message || error);
                    }
                });
            }, index * 100); // Delay de 100ms entre cada request
        });
    }
}

/**
 * Actualiza el carrito en localStorage después de una operación
 */
function actualizarCarritoLocalStorage(carrito) {
    guardarCarritoLocalStorage(carrito);
}

/**
 * Limpia el carrito de localStorage
 */
function limpiarCarritoLocalStorage() {
    try {
        localStorage.removeItem(CARRITO_STORAGE_KEY);
        console.log('Carrito limpiado de localStorage');
    } catch (error) {
        console.error('Error al limpiar carrito de localStorage:', error);
    }
}

// Sincronizar carrito al cargar la página (solo si hay items)
document.addEventListener('DOMContentLoaded', function() {
    // Esperar un momento para que la página cargue completamente
    setTimeout(() => {
        const carritoLocal = cargarCarritoLocalStorage();
        // Solo sincronizar si hay items y no estamos en la página de carrito
        if (carritoLocal && carritoLocal.length > 0 && !window.location.pathname.includes('/carrito')) {
            sincronizarCarritoConServidor();
        }
    }, 500);
});
