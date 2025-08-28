/**
 * AudiThor - Security Dashboard
 * Fichero principal de la lógica de la aplicación.
 * Versión inicial solo para la carga de iconos.
 */

/**
 * Carga dinámicamente los iconos SVG en la barra lateral.
 * Lee los iconos del objeto global SIDEBAR_ICONS (que debe estar definido en icons.js).
 */
const loadSidebarIcons = () => {
    // Primero, manejamos el logo principal, que es un caso especial
    const logoContainer = document.querySelector('aside .flex.items-center.justify-center');
    if (logoContainer && SIDEBAR_ICONS && SIDEBAR_ICONS.logo) {
        logoContainer.insertAdjacentHTML('afterbegin', SIDEBAR_ICONS.logo);
    }

    // Luego, recorremos todos los enlaces de navegación
    const navLinks = document.querySelectorAll('#sidebar-nav .main-nav-link');
    navLinks.forEach(link => {
        const viewName = link.dataset.view;
        // Si existe un icono para esta vista en nuestro objeto SIDEBAR_ICONS
        if (SIDEBAR_ICONS && SIDEBAR_ICONS[viewName]) {
            // Lo insertamos justo al principio del enlace <a>
            link.insertAdjacentHTML('afterbegin', SIDEBAR_ICONS[viewName]);
        }
    });
};

/**
 * Punto de entrada de la aplicación.
 * Se ejecuta cuando el contenido del HTML ha sido completamente cargado.
 */
document.addEventListener('DOMContentLoaded', () => {
    // Llamamos a la función para cargar los iconos tan pronto como la página esté lista.
    loadSidebarIcons();

    // Aquí irás añadiendo el resto de la lógica de tu aplicación,
    // como los selectores de elementos y los event listeners.
});