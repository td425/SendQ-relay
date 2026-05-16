// Apply persisted theme (or system preference) before paint to avoid FOUC.
// Loaded synchronously from <head> so the data-theme attribute is set on
// <html> before the stylesheet's CSS variables resolve.
(function () {
  try {
    var t = localStorage.getItem('sendq_theme');
    if (t !== 'light' && t !== 'dark') {
      t = (window.matchMedia &&
           window.matchMedia('(prefers-color-scheme: light)').matches)
        ? 'light' : 'dark';
    }
    document.documentElement.setAttribute('data-theme', t);
  } catch (e) {}
})();
