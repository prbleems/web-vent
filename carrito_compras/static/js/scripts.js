// El formulario ahora se envía directamente a Flask
// Este script solo maneja la validación del lado del cliente si es necesario
document.getElementById("loginForm").addEventListener("submit", function (event) {
    const usuarioInput = document.querySelector('input[name="usuario"]').value;
    const passwordInput = document.querySelector('input[name="password"]').value;

    // Validación básica del lado del cliente
    if (!usuarioInput || !passwordInput) {
        event.preventDefault();
        const errorMessage = document.getElementById("error-message");
        errorMessage.innerHTML = "<p style='color: red; font-family: \"Courier New\", Courier, monospace;'>Por favor complete todos los campos.</p>";
        errorMessage.style.display = "block";
    }
});
