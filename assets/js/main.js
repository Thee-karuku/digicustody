/**
 * DigiCustody – Global JavaScript
 */

// Universal back button using browser history
function goBack() {
    if (window.history.length > 1) {
        const referrer = document.referrer;
        if (referrer && referrer !== window.location.href) {
            window.history.back();
        } else {
            window.location.href = 'dashboard.php';
        }
    } else {
        window.location.href = 'dashboard.php';
    }
}

// Close dropdowns on outside click
document.addEventListener('click', function(e) {
    if (!e.target.closest('#notifWrap')) {
        var nd = document.getElementById('notifDropdown');
        if (nd) nd.classList.remove('open');
    }
    if (!e.target.closest('#userMenuWrap')) {
        var ud = document.getElementById('userDropdown');
        if (ud) ud.classList.remove('open');
    }
});

// Sidebar toggle
function toggleSidebar() {
    var sb = document.getElementById('sidebar');
    var ma = document.getElementById('mainArea');
    var ol = document.getElementById('sidebarOverlay');
    if (!sb || !ma) return;
    if (window.innerWidth <= 768) {
        sb.classList.toggle('mobile-open');
        if (ol) ol.classList.toggle('active');
    } else {
        sb.classList.toggle('collapsed');
        ma.classList.toggle('collapsed');
    }
    localStorage.setItem('sb_collapsed', sb.classList.contains('collapsed') ? '1' : '0');
}

// Restore sidebar state
(function() {
    if (localStorage.getItem('sb_collapsed') === '1' && window.innerWidth > 900) {
        var sb = document.getElementById('sidebar');
        var ma = document.getElementById('mainArea');
        if (sb) sb.classList.add('collapsed');
        if (ma) ma.classList.add('collapsed');
    }
})();

// Global search handler
function handleSearch(e) {
    if (e.key === 'Enter') {
        var v = document.getElementById('globalSearch');
        if (v && v.value.trim()) {
            window.location = 'evidence.php?search=' + encodeURIComponent(v.value.trim());
        }
    }
}

// Dropdown toggles
function toggleNotif() {
    var nd = document.getElementById('notifDropdown');
    var ud = document.getElementById('userDropdown');
    if (nd) nd.classList.toggle('open');
    if (ud) ud.classList.remove('open');
}

function toggleUserMenu() {
    var ud = document.getElementById('userDropdown');
    var nd = document.getElementById('notifDropdown');
    if (ud) ud.classList.toggle('open');
    if (nd) nd.classList.remove('open');
}
