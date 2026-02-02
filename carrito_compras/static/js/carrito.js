// Funciones para manejar el carrito de compras

function actualizarCantidad(productoId, talla, cambio) {
    fetch('/actualizar_cantidad', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            producto_id: productoId,
            talla: talla,
            cambio: cambio
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Actualizar localStorage si está disponible
            if (typeof guardarCarritoLocalStorage === 'function') {
                // Obtener el carrito actualizado del servidor
                fetch('/carrito')
                    .then(response => response.text())
                    .then(html => {
                        // Parsear el HTML para obtener el carrito (simplificado)
                        // Por ahora, recargamos la página
                        window.location.reload();
                    });
            } else {
                if (typeof notificarExito === 'function') {
                    notificarExito('Cantidad actualizada');
                }
                setTimeout(() => window.location.reload(), 500);
            }
        } else {
            if (typeof notificarError === 'function') {
                notificarError('Error al actualizar la cantidad');
            } else {
                alert('Error al actualizar la cantidad');
            }
        }
    })
    .catch(error => {
        console.error('Error:', error);
        if (typeof notificarError === 'function') {
            notificarError('Error al actualizar la cantidad');
        } else {
            alert('Error al actualizar la cantidad');
        }
    });
}

function eliminarProducto(productoId, talla) {
    const confirmar = confirm('¿Estás seguro de que quieres eliminar este producto del carrito?');
    if (confirmar) {
        fetch('/eliminar_producto', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                producto_id: productoId,
                talla: talla
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Actualizar localStorage si está disponible
                if (typeof limpiarCarritoLocalStorage === 'function') {
                    // Obtener el carrito actualizado del servidor
                    fetch('/carrito')
                        .then(response => response.text())
                        .then(html => {
                            // Por ahora, recargamos la página
                            window.location.reload();
                        });
                } else {
                    if (typeof notificarExito === 'function') {
                        notificarExito('Producto eliminado del carrito');
                    }
                    setTimeout(() => window.location.reload(), 500);
                }
            } else {
                if (typeof notificarError === 'function') {
                    notificarError('Error al eliminar el producto');
                } else {
                    alert('Error al eliminar el producto');
                }
            }
        })
        .catch(error => {
            console.error('Error:', error);
            if (typeof notificarError === 'function') {
                notificarError('Error al eliminar el producto');
            } else {
                alert('Error al eliminar el producto');
            }
        });
    }
}
