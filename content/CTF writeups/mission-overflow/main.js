import Desktop from './Desktop.js';

document.addEventListener('DOMContentLoaded', () => {
    const desktopEl = document.getElementById('desktop');
    const taskbarAppsEl = document.getElementById('taskbar-apps');

    // Pass them all to the Desktop constructor
   new Desktop(desktopEl, taskbarAppsEl);
});