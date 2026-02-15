(function() {
    var overlay = document.getElementById('vent-modal-usuario-overlay');
    var openBtn = document.getElementById('vent-open-modal-usuario');
    var closeBtn = document.getElementById('vent-close-modal-usuario');
    var modalGuest = document.getElementById('vent-modal-guest');
    var modalLogged = document.getElementById('vent-modal-logged');
    var ventClienteActual = null;

    function openModal() {
        if (overlay) {
            overlay.classList.add('vent-modal-open');
            overlay.setAttribute('aria-hidden', 'false');
            document.body.style.overflow = 'hidden';
            loadPerfil();
        }
    }

    function closeModal() {
        if (overlay) {
            overlay.classList.remove('vent-modal-open');
            overlay.setAttribute('aria-hidden', 'true');
            document.body.style.overflow = '';
        }
    }

    function showMsg(el, text, isError) {
        if (!el) return;
        el.textContent = text || '';
        el.className = 'vent-msg' + (isError ? ' vent-msg-error' : ' vent-msg-ok');
    }

    function switchGuestTabs() {
        document.querySelectorAll('#vent-modal-guest .vent-tab').forEach(function(t) {
            t.addEventListener('click', function() {
                var tab = this.getAttribute('data-tab');
                document.querySelectorAll('#vent-modal-guest .vent-tab').forEach(function(x) { x.classList.remove('vent-tab-active'); });
                document.querySelectorAll('#vent-modal-guest .vent-tab-panel').forEach(function(x) { x.classList.remove('vent-tab-panel-active'); });
                this.classList.add('vent-tab-active');
                var panel = document.getElementById('vent-tab-' + tab);
                if (panel) panel.classList.add('vent-tab-panel-active');
            });
        });
    }

    function switchLoggedTabs() {
        document.querySelectorAll('#vent-modal-logged .vent-tab').forEach(function(t) {
            t.addEventListener('click', function() {
                var tab = this.getAttribute('data-tab');
                document.querySelectorAll('#vent-modal-logged .vent-tab').forEach(function(x) { x.classList.remove('vent-tab-active'); });
                document.querySelectorAll('#vent-modal-logged .vent-tab-panel').forEach(function(x) { x.classList.remove('vent-tab-panel-active'); });
                this.classList.add('vent-tab-active');
                var panel = document.getElementById('vent-tab-' + tab);
                if (panel) panel.classList.add('vent-tab-panel-active');
            });
        });
    }

    function formatPrecio(n) {
        return '$' + (typeof n === 'number' ? n : parseFloat(n || 0)).toLocaleString('es-CL', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
    }

    function formatFecha(s) {
        if (!s) return '-';
        var d = new Date(s);
        if (isNaN(d.getTime())) return s;
        return d.toLocaleDateString('es-CL', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
    }

    function renderLoggedIn(data) {
        if (!data.cliente) return;
        var c = data.cliente;
        var pedidos = data.pedidos || [];
        ventClienteActual = c;

        modalGuest.style.display = 'none';
        modalLogged.style.display = 'block';

        var listEl = document.getElementById('vent-pedidos-list');
        if (listEl) {
            if (!pedidos || pedidos.length === 0) {
                listEl.innerHTML = '<p class="vent-empty">Aún no tienes pedidos.</p>';
            } else {
                listEl.innerHTML = pedidos.map(function(p) {
                    return '<div class="vent-pedido-item">' +
                        '<div class="vent-pedido-num">' + (p.numero_pedido || 'Pedido #' + p.id) + '</div>' +
                        '<div>Total: ' + formatPrecio(p.total) + '</div>' +
                        '<span class="vent-pedido-estado">' + (p.estado || 'pendiente') + '</span>' +
                        '<div class="vent-pedido-fecha">' + formatFecha(p.fecha) + '</div>' +
                        '</div>';
                }).join('');
            }
        }

        var emailEl = document.getElementById('vent-upd-email');
        var nombreDatosEl = document.getElementById('vent-upd-nombre-datos');
        var telefonoDatosEl = document.getElementById('vent-upd-telefono-datos');
        if (emailEl) emailEl.value = c.email || '';
        if (nombreDatosEl) nombreDatosEl.value = c.nombre || '';
        if (telefonoDatosEl) telefonoDatosEl.value = c.telefono || '';

        document.getElementById('vent-upd-nombre').value = c.nombre || '';
        document.getElementById('vent-upd-telefono').value = c.telefono || '';
        document.getElementById('vent-upd-direccion').value = c.direccion || '';
        document.getElementById('vent-upd-comuna').value = c.comuna || '';
        document.getElementById('vent-upd-region').value = c.region || '';
    }

    function renderGuest() {
        modalGuest.style.display = 'block';
        modalLogged.style.display = 'none';
        showMsg(document.getElementById('vent-login-msg'), '');
        showMsg(document.getElementById('vent-register-msg'), '');
    }

    function loadPerfil() {
        fetch('/api/cliente/perfil')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.logged_in && data.cliente) {
                    renderLoggedIn(data);
                    switchLoggedTabs();
                } else {
                    renderGuest();
                    switchGuestTabs();
                }
            })
            .catch(function() {
                renderGuest();
                switchGuestTabs();
            });
    }

    if (openBtn) openBtn.addEventListener('click', openModal);
    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    if (overlay) {
        overlay.addEventListener('click', function(e) {
            if (e.target === overlay) closeModal();
        });
    }

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && overlay && overlay.classList.contains('vent-modal-open')) closeModal();
    });

    var formLogin = document.getElementById('vent-form-login');
    if (formLogin) {
        formLogin.addEventListener('submit', function(e) {
            e.preventDefault();
            var msgEl = document.getElementById('vent-login-msg');
            var btn = document.getElementById('vent-btn-login');
            var email = document.getElementById('vent-login-email').value.trim().toLowerCase();
            var password = document.getElementById('vent-login-password').value;
            if (!email || !password) {
                showMsg(msgEl, 'Completa email y contraseña', true);
                return;
            }
            btn.disabled = true;
            var textoOriginal = btn.textContent;
            btn.textContent = 'Verificando...';
            showMsg(msgEl, '');
            fetch('/api/cliente/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email, password: password })
            })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.success) {
                    if (typeof notificarExito === 'function') notificarExito('Sesión iniciada');
                    loadPerfil();
                } else {
                    showMsg(msgEl, data.error || 'Error al iniciar sesión', true);
                }
            })
            .catch(function() {
                showMsg(msgEl, 'Error de conexión', true);
            })
            .finally(function() {
                btn.disabled = false;
                btn.textContent = textoOriginal || 'Entrar';
            });
        });
    }

    var olvidoPassword = document.getElementById('vent-olvido-password');
    if (olvidoPassword) {
        olvidoPassword.addEventListener('click', function(e) {
            e.preventDefault();
            var msgEl = document.getElementById('vent-login-msg');
            showMsg(msgEl, 'La recuperación por correo no está disponible por el momento.', true);
        });
    }

    var formRegister = document.getElementById('vent-form-register');
    if (formRegister) {
        formRegister.addEventListener('submit', function(e) {
            e.preventDefault();
            var msgEl = document.getElementById('vent-register-msg');
            var btn = document.getElementById('vent-btn-register');
            var payload = {
                nombre: document.getElementById('vent-reg-nombre').value.trim(),
                email: document.getElementById('vent-reg-email').value.trim().toLowerCase(),
                password: document.getElementById('vent-reg-password').value,
                telefono: document.getElementById('vent-reg-telefono').value.trim() || null,
                direccion: document.getElementById('vent-reg-direccion').value.trim() || null,
                comuna: document.getElementById('vent-reg-comuna').value.trim() || null,
                region: document.getElementById('vent-reg-region').value.trim() || null
            };
            if (!payload.nombre || !payload.email || payload.password.length < 8) {
                showMsg(msgEl, 'Nombre, email y contraseña (mín. 8 caracteres) son obligatorios', true);
                return;
            }
            btn.disabled = true;
            showMsg(msgEl, '');
            fetch('/api/cliente/registro', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.success) {
                    if (typeof notificarExito === 'function') notificarExito('Cuenta creada');
                    loadPerfil();
                } else {
                    showMsg(msgEl, data.error || 'Error al crear cuenta', true);
                }
            })
            .catch(function() {
                showMsg(msgEl, 'Error de conexión', true);
            })
            .finally(function() { btn.disabled = false; });
        });
    }

    var btnLogout = document.getElementById('vent-btn-logout');
    if (btnLogout) {
        btnLogout.addEventListener('click', function() {
            fetch('/api/cliente/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' } })
                .then(function() {
                    renderGuest();
                    switchGuestTabs();
                    if (typeof notificarExito === 'function') notificarExito('Sesión cerrada');
                });
        });
    }

    var formUpdateDatos = document.getElementById('vent-form-actualizar-datos');
    if (formUpdateDatos) {
        formUpdateDatos.addEventListener('submit', function(e) {
            e.preventDefault();
            var msgEl = document.getElementById('vent-update-datos-msg');
            var nombre = document.getElementById('vent-upd-nombre-datos').value.trim();
            var telefono = document.getElementById('vent-upd-telefono-datos').value.trim() || null;
            if (!nombre) {
                showMsg(msgEl, 'El nombre es obligatorio', true);
                return;
            }
            var payload = {
                nombre: nombre,
                telefono: telefono,
                direccion: (ventClienteActual && ventClienteActual.direccion) || null,
                comuna: (ventClienteActual && ventClienteActual.comuna) || null,
                region: (ventClienteActual && ventClienteActual.region) || null
            };
            fetch('/api/cliente/actualizar', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.success) {
                    showMsg(msgEl, 'Datos personales guardados', false);
                    if (typeof notificarExito === 'function') notificarExito('Datos actualizados');
                    loadPerfil();
                } else {
                    showMsg(msgEl, data.error || 'Error al guardar', true);
                }
            })
            .catch(function() {
                showMsg(msgEl, 'Error de conexión', true);
            });
        });
    }

    var formCambiarPassword = document.getElementById('vent-form-cambiar-password');
    if (formCambiarPassword) {
        formCambiarPassword.addEventListener('submit', function(e) {
            e.preventDefault();
            var msgEl = document.getElementById('vent-cambiar-password-msg');
            var passwordActual = document.getElementById('vent-password-actual').value;
            var passwordNueva = document.getElementById('vent-password-nueva').value;
            var passwordConfirmar = document.getElementById('vent-password-confirmar').value;
            if (!passwordActual) {
                showMsg(msgEl, 'Indica tu contraseña actual', true);
                return;
            }
            if (passwordNueva.length < 8) {
                showMsg(msgEl, 'La nueva contraseña debe tener al menos 8 caracteres', true);
                return;
            }
            if (passwordNueva !== passwordConfirmar) {
                showMsg(msgEl, 'La nueva contraseña y la confirmación no coinciden', true);
                return;
            }
            showMsg(msgEl, '');
            fetch('/api/cliente/cambiar-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password_actual: passwordActual, password_nueva: passwordNueva })
            })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.success) {
                    showMsg(msgEl, 'Contraseña actualizada correctamente', false);
                    if (typeof notificarExito === 'function') notificarExito('Contraseña actualizada');
                    formCambiarPassword.reset();
                } else {
                    showMsg(msgEl, data.error || 'Error al cambiar contraseña', true);
                }
            })
            .catch(function() {
                showMsg(msgEl, 'Error de conexión', true);
            });
        });
    }

    var formUpdate = document.getElementById('vent-form-actualizar-envio');
    if (formUpdate) {
        formUpdate.addEventListener('submit', function(e) {
            e.preventDefault();
            var msgEl = document.getElementById('vent-update-msg');
            var payload = {
                nombre: document.getElementById('vent-upd-nombre').value.trim(),
                telefono: document.getElementById('vent-upd-telefono').value.trim() || null,
                direccion: document.getElementById('vent-upd-direccion').value.trim() || null,
                comuna: document.getElementById('vent-upd-comuna').value.trim() || null,
                region: document.getElementById('vent-upd-region').value.trim() || null
            };
            if (!payload.nombre) {
                showMsg(msgEl, 'El nombre es obligatorio', true);
                return;
            }
            fetch('/api/cliente/actualizar', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.success) {
                    showMsg(msgEl, 'Datos de envío guardados', false);
                    if (typeof notificarExito === 'function') notificarExito('Datos actualizados');
                    loadPerfil();
                } else {
                    showMsg(msgEl, data.error || 'Error al guardar', true);
                }
            })
            .catch(function() {
                showMsg(msgEl, 'Error de conexión', true);
            });
        });
    }
})();
