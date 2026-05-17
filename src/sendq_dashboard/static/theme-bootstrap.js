// Apply persisted theme before paint to avoid FOUC. Loaded synchronously
// from <head> so the data-theme attribute is set on <html> before the
// stylesheet's CSS variables resolve.
//
// Default: light. We intentionally ignore prefers-color-scheme so the
// dashboard looks the same for everyone out of the box — operators have
// asked for a white default. The Switch theme button still flips and
// persists per browser.
(function () {
  try {
    var t = localStorage.getItem('sendq_theme');
    if (t !== 'light' && t !== 'dark') t = 'light';
    document.documentElement.setAttribute('data-theme', t);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'light');
  }
})();
