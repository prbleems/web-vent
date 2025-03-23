// script.js
function updateTime() {
    const now = new Date();
    
    // Formato MM/DD/YYYY
    const month = String(now.getMonth() + 1).padStart(2, '0'); // Mes (0-11)
    const day = String(now.getDate()).padStart(2, '0'); // Día (1-31)
    const year = now.getFullYear(); // Año (YYYY)

    // Formato hh:mm a
    let hours = now.getHours();
    const minutes = String(now.getMinutes()).padStart(2, '0'); // Minutos (0-59)
    const ampm = hours >= 12 ? 'pm' : 'am'; // AM/PM
    hours = hours % 12; // Convertir a formato de 12 horas
    hours = hours ? String(hours).padStart(2, '0') : '12'; // Asegurarse de que sea '12' si es mediodía

    const dateString = `${month}/${day}/${year}`;
    const timeString = `${hours}:${minutes}${ampm}`;

    document.getElementById('time').innerHTML = `${dateString} ${timeString}`;
}

// Actualiza la hora y el día cada segundo
setInterval(updateTime, 1000);

// Llama a la función una vez para mostrar inmediatamente al cargar la página
updateTime();
