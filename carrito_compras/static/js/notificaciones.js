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

/**
 * Confirmación estilo VENT (reemplaza confirm() nativo)
 * @param {string} mensaje - Pregunta a mostrar
 * @param {function} onAceptar - Se ejecuta al pulsar Aceptar
 * @param {function} onCancelar - Opcional, al pulsar Cancelar
 */
function confirmarVent(mensaje, onAceptar, onCancelar) {
    var overlay = document.createElement('div');
    overlay.className = 'vent-confirm-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-labelledby', 'vent-confirm-titulo');

    var box = document.createElement('div');
    box.className = 'vent-confirm-box';
    box.innerHTML =
        '<p class="vent-confirm-titulo" id="vent-confirm-titulo">' + mensaje + '</p>' +
        '<div class="vent-confirm-btns">' +
        '<button type="button" class="vent-confirm-btn vent-confirm-cancelar">Cancelar</button>' +
        '<button type="button" class="vent-confirm-btn vent-confirm-aceptar">Aceptar</button>' +
        '</div>';

    overlay.appendChild(box);
    document.body.appendChild(overlay);

    function cerrar(resultado) {
        overlay.classList.add('vent-confirm-out');
        setTimeout(function() {
            if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
        }, 200);
        if (resultado === true && typeof onAceptar === 'function') onAceptar();
        if (resultado === false && typeof onCancelar === 'function') onCancelar();
    }

    box.querySelector('.vent-confirm-aceptar').addEventListener('click', function() { cerrar(true); });
    box.querySelector('.vent-confirm-cancelar').addEventListener('click', function() { cerrar(false); });
    overlay.addEventListener('click', function(e) {
        if (e.target === overlay) cerrar(false);
    });
    document.addEventListener('keydown', function tecla(e) {
        if (e.key === 'Escape') {
            cerrar(false);
            document.removeEventListener('keydown', tecla);
        }
    });
}

// Estilos del modal de confirmación VENT
if (!document.getElementById('vent-confirm-styles')) {
    var styleConfirm = document.createElement('style');
    styleConfirm.id = 'vent-confirm-styles';
    styleConfirm.textContent = [
        '.vent-confirm-overlay {',
        '  position: fixed; top: 0; left: 0; right: 0; bottom: 0;',
        '  background: rgba(0,0,0,0.4);',
        '  z-index: 10001;',
        '  display: flex; align-items: center; justify-content: center;',
        '  padding: 20px;',
        '  box-sizing: border-box;',
        '  animation: ventConfirmFadeIn 0.2s ease-out;',
        '}',
        '.vent-confirm-overlay.vent-confirm-out { animation: ventConfirmFadeOut 0.2s ease-in forwards; }',
        '.vent-confirm-box {',
        '  background: #fff;',
        '  border: 2px solid #000;',
        '  padding: 28px 32px;',
        '  max-width: 400px;',
        '  width: 100%;',
        '  font-family: "Courier New", Courier, monospace;',
        '  animation: ventConfirmSlide 0.25s ease-out;',
        '}',
        '.vent-confirm-titulo {',
        '  margin: 0 0 24px 0;',
        '  font-size: 14px;',
        '  line-height: 1.5;',
        '  color: #000;',
        '  text-transform: uppercase;',
        '  letter-spacing: 0.5px;',
        '}',
        '.vent-confirm-btns {',
        '  display: flex;',
        '  gap: 12px;',
        '  justify-content: flex-end;',
        '}',
        '.vent-confirm-btn {',
        '  padding: 12px 24px;',
        '  border: 2px solid #000;',
        '  background: #fff;',
        '  color: #000;',
        '  font-family: "Courier New", Courier, monospace;',
        '  font-size: 12px;',
        '  text-transform: uppercase;',
        '  letter-spacing: 1px;',
        '  cursor: pointer;',
        '  transition: background 0.2s, color 0.2s;',
        '}',
        '.vent-confirm-btn:hover {',
        '  background: #000;',
        '  color: #fff;',
        '}',
        '.vent-confirm-aceptar { background: #000; color: #fff; }',
        '.vent-confirm-aceptar:hover { background: #333; color: #fff; }',
        '@keyframes ventConfirmFadeIn { from { opacity: 0; } to { opacity: 1; } }',
        '@keyframes ventConfirmFadeOut { from { opacity: 1; } to { opacity: 0; } }',
        '@keyframes ventConfirmSlide { from { opacity: 0; transform: scale(0.96); } to { opacity: 1; transform: scale(1); } }'
    ].join('\n');
    document.head.appendChild(styleConfirm);
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
