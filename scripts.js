document.getElementById("loginForm").addEventListener("submit", function (event) {
    event.preventDefault(); // Evitar el envío del formulario

    // Usuario y contraseña guardados
    const storedUser = "1"; // Cambia esto por el usuario deseado
    const storedPassword = "1"; // Cambia esto por la contraseña deseada

    // Obtener valores ingresados
    const usuarioInput = document.querySelector('input[name="usuario"]').value;
    const passwordInput = document.querySelector('input[name="password"]').value;

    // Verificar las credenciales
    if (usuarioInput === storedUser && passwordInput === storedPassword) {
        // Redirigir si las credenciales son correctas
        window.location.href = "pages/inicio.html";
    } else {
        // Mostrar mensaje de error si son incorrectas
        const errorMessage = document.getElementById("error-message");
        errorMessage.textContent = "Contraseña incorrecta.";
        errorMessage.style.display = "block";
        errorMessage.style.fontFamily = '"Courier New", Courier, monospace';
    }
});
