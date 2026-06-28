window.addEventListener('load', () => {
    const scrollbox = document.querySelector('.sidebar .sidebar-scrollbox');
    if (!scrollbox) return;

    const link = document.createElement('a');
    link.href = '/';
    link.className = 'sidebar-logo';
    link.title = 'Sesam — Git Secrets Management';
    scrollbox.prepend(link);
});
