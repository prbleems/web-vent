// Funciones para manejar el carrito de compras (AJAX, sin recargar página)

function formatPrice(price) {
    return '$' + (typeof price === 'number' ? price : parseFloat(price || 0)).toLocaleString('es-CL', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
}

function actualizarResumenEnDOM(totales) {
    var subtotalEl = document.getElementById('subtotalDisplay');
    var costoEnvioEl = document.getElementById('costoEnvio');
    var descuentoEl = document.getElementById('descuentoDisplay');
    var totalEl = document.getElementById('totalFinal');
    if (subtotalEl) subtotalEl.textContent = formatPrice(totales.total_subtotal);
    if (costoEnvioEl) costoEnvioEl.textContent = formatPrice(totales.costo_envio);
    if (descuentoEl) descuentoEl.textContent = '-' + formatPrice(totales.descuento);
    if (totalEl) totalEl.textContent = formatPrice(totales.total);
}

function actualizarCantidad(productoId, talla, cambio) {
    fetch('/actualizar_cantidad', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            producto_id: productoId,
            talla: talla || 'Talla Única',
            cambio: cambio
        })
    })
    .then(function(response) {
        return response.json().catch(function() { return { success: false, error: 'Error de conexión' }; }).then(function(data) {
            if (!response.ok) return { success: false, error: (data && data.error) || ('Error ' + response.status) };
            return data;
        });
    })
    .then(function(data) {
        if (data.success) {
            if (typeof guardarCarritoLocalStorage === 'function' && data.carrito) {
                guardarCarritoLocalStorage(data.carrito);
            }
            // Actualizar DOM sin recargar
            var row = document.querySelector('.producto-item[data-producto-id="' + productoId + '"][data-talla="' + (talla || 'Talla Única').replace(/"/g, '&quot;') + '"]');
            if (row) {
                var cantidadValor = row.querySelector('.cantidad-valor');
                var subtotalValor = row.querySelector('.subtotal-valor');
                var precio = parseFloat(row.getAttribute('data-precio')) || 0;
                var nuevaCantidad = parseInt(cantidadValor.textContent, 10) + cambio;
                if (nuevaCantidad <= 0) {
                    row.remove();
                } else {
                    cantidadValor.textContent = nuevaCantidad;
                    if (subtotalValor) subtotalValor.textContent = formatPrice(precio * nuevaCantidad);
                }
            }
            if (data.total_subtotal !== undefined) {
                actualizarResumenEnDOM({
                    total_subtotal: data.total_subtotal,
                    costo_envio: data.costo_envio,
                    descuento: data.descuento,
                    total: data.total
                });
            }
            if (typeof window.actualizarTotalesCarrito === 'function') {
                window.actualizarTotalesCarrito(data.total_subtotal, data.descuento, data.costo_envio, data.total);
            }
            if (data.carrito && data.carrito.length === 0) {
                window.location.reload();
                return;
            }
            if (typeof notificarExito === 'function') {
                notificarExito('Cantidad actualizada');
            }
        } else {
            if (typeof notificarError === 'function') {
                notificarError(data.error || 'Error al actualizar la cantidad');
            } else {
                alert(data.error || 'Error al actualizar la cantidad');
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
    var confirmar = confirm('¿Estás seguro de que quieres eliminar este producto del carrito?');
    if (!confirmar) return;
    fetch('/eliminar_producto', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            producto_id: productoId,
            talla: talla || 'Talla Única'
        })
    })
    .then(response => {
        return response.json().catch(function() { return { success: false, error: 'Error de conexión' }; }).then(function(data) {
            if (!response.ok) return { success: false, error: (data && data.error) || ('Error ' + response.status) };
            return data;
        });
    })
    .then(data => {
        if (data.success) {
            if (typeof guardarCarritoLocalStorage === 'function' && data.carrito) {
                guardarCarritoLocalStorage(data.carrito);
            }
            var row = document.querySelector('.producto-item[data-producto-id="' + productoId + '"][data-talla="' + (talla || 'Talla Única').replace(/"/g, '&quot;') + '"]');
            if (row) row.remove();
            if (data.total_subtotal !== undefined) {
                actualizarResumenEnDOM({
                    total_subtotal: data.total_subtotal,
                    costo_envio: data.costo_envio,
                    descuento: data.descuento,
                    total: data.total
                });
            }
            if (typeof window.actualizarTotalesCarrito === 'function') {
                window.actualizarTotalesCarrito(data.total_subtotal, data.descuento, data.costo_envio, data.total);
            }
            if (data.carrito && data.carrito.length === 0) {
                window.location.reload();
                return;
            }
            if (typeof notificarExito === 'function') {
                notificarExito('Producto eliminado del carrito');
            }
        } else {
            if (typeof notificarError === 'function') {
                notificarError(data.error || 'Error al eliminar el producto');
            } else {
                alert(data.error || 'Error al eliminar el producto');
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
