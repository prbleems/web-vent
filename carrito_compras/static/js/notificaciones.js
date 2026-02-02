// Sistema de notificaciones para VENT
// Estilo minimalista blanco y negro

/**
 * Muestra una notificación al usuario
 * @param {string} mensaje - Mensaje a mostrar
 * @param {string} tipo - Tipo de notificación: 'success', 'error', 'info', 'warning'
 * @param {number} duracion - Duración en milisegundos (default: 3000)
 */
function mostrarNotificacion(mensaje, tipo = 'info', duracion = 3000) {
    // Crear contenedor de notificaciones si no existe
    let container = document.getElementById('notificaciones-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notificaciones-container';
        container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            display: flex;
            flex-direction: column;
            gap: 10px;
            pointer-events: none;
        `;
        document.body.appendChild(container);
    }
    
    // Crear notificación
    const notificacion = document.createElement('div');
    notificacion.className = `notificacion notificacion-${tipo}`;
    
    // Estilos base
    const estilosBase = {
        backgroundColor: '#000',
        color: '#fff',
        padding: '15px 25px',
        border: '2px solid #000',
        fontFamily: '"Courier New", Courier, monospace',
        fontSize: '14px',
        minWidth: '300px',
        maxWidth: '400px',
        boxShadow: '0 4px 8px rgba(0, 0, 0, 0.3)',
        animation: 'slideInRight 0.3s ease-out',
        pointerEvents: 'auto',
        cursor: 'pointer',
        position: 'relative'
    };
    
    // Aplicar estilos según tipo
    if (tipo === 'success') {
        estilosBase.backgroundColor = '#000';
        estilosBase.color = '#fff';
    } else if (tipo === 'error') {
        estilosBase.backgroundColor = '#000';
        estilosBase.color = '#fff';
        estilosBase.borderColor = '#ff0000';
    } else if (tipo === 'warning') {
        estilosBase.backgroundColor = '#000';
        estilosBase.color = '#fff';
    } else {
        estilosBase.backgroundColor = '#000';
        estilosBase.color = '#fff';
    }
    
    // Aplicar estilos
    Object.assign(notificacion.style, estilosBase);
    
    // Icono según tipo
    let icono = '';
    if (tipo === 'success') {
        icono = '✓';
    } else if (tipo === 'error') {
        icono = '✗';
    } else if (tipo === 'warning') {
        icono = '⚠';
    } else {
        icono = 'ℹ';
    }
    
    notificacion.innerHTML = `
        <span style="margin-right: 10px; font-weight: bold;">${icono}</span>
        <span>${mensaje}</span>
    `;
    
    // Agregar al contenedor
    container.appendChild(notificacion);
    
    // Auto-remover después de la duración
    const timeout = setTimeout(() => {
        notificarCerrar(notificacion);
    }, duracion);
    
    // Cerrar al hacer click
    notificacion.addEventListener('click', () => {
        clearTimeout(timeout);
        notificarCerrar(notificacion);
    });
    
    return notificacion;
}

/**
 * Cierra una notificación con animación
 */
function notificarCerrar(notificacion) {
    notificacion.style.animation = 'slideOutRight 0.3s ease-out';
    setTimeout(() => {
        if (notificacion.parentNode) {
            notificacion.parentNode.removeChild(notificacion);
        }
    }, 300);
}

/**
 * Notificación de éxito
 */
function notificarExito(mensaje, duracion = 3000) {
    return mostrarNotificacion(mensaje, 'success', duracion);
}

/**
 * Notificación de error
 */
function notificarError(mensaje, duracion = 4000) {
    return mostrarNotificacion(mensaje, 'error', duracion);
}

/**
 * Notificación de información
 */
function notificarInfo(mensaje, duracion = 3000) {
    return mostrarNotificacion(mensaje, 'info', duracion);
}

/**
 * Notificación de advertencia
 */
function notificarAdvertencia(mensaje, duracion = 3500) {
    return mostrarNotificacion(mensaje, 'warning', duracion);
}

// Agregar estilos de animación si no existen
if (!document.getElementById('notificaciones-styles')) {
    const style = document.createElement('style');
    style.id = 'notificaciones-styles';
    style.textContent = `
        @keyframes slideInRight {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        @keyframes slideOutRight {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(100%);
                opacity: 0;
            }
        }
        
        .notificacion:hover {
            background-color: #fff !important;
            color: #000 !important;
            border-color: #000 !important;
        }
    `;
    document.head.appendChild(style);
}
