// script.js - Formato de fecha y hora VENT
function updateTime() {
    const now = new Date();
    
    // Formato DD/MM/YYYY (formato chileno)
    const day = String(now.getDate()).padStart(2, '0');
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const year = now.getFullYear();

    // Formato hh:mm (24 horas)
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');

    const dateString = `${day}/${month}/${year}`;
    const timeString = `${hours}:${minutes}`;

    // Formato: "02/02/2026 14:21 VENT"
    const timeElement = document.getElementById('time');
    if (timeElement) {
        timeElement.innerHTML = `${dateString} ${timeString} VENT`;
    }
}

// Actualiza la hora y el día cada segundo
setInterval(updateTime, 1000);

// Llama a la función una vez para mostrar inmediatamente al cargar la página
updateTime();
