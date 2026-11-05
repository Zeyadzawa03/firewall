/* ================================================
   FORTINET KNOWLEDGE BASE — Application Logic
   Navigation, Search, Rendering, Theme Management
   ================================================ */

(function () {
    'use strict';

    // ========================================
    // NAVIGATION TREE
    // ========================================
    const NAV_TREE = [
        {
            id: '_welcome', title: 'Welcome', icon: '🏠', type: 'page'
        },
        {
            id: '_fortigate_header', title: 'FortiGate Firewall', icon: '🛡️', type: 'section',
            children: [
                { id: 'fg-dashboard', title: 'Dashboard', icon: '📊' },
                {
                    id: '_fg_system', title: 'System', icon: '⚙️', type: 'group',
                    children: [
                        { id: 'fg-system', title: 'System Settings', icon: '⚙️' },
                        { id: 'fg-interfaces', title: 'Interfaces', icon: '🔌' },
                        { id: 'fg-zones', title: 'Zones', icon: '📦' },
                        { id: 'fg-vdoms', title: 'VDOMs', icon: '🏗️' },
                        { id: 'fg-administrators', title: 'Administrators', icon: '👤' },
                        { id: 'fg-certificates', title: 'Certificates', icon: '📜' },
                        { id: 'fg-dns', title: 'DNS', icon: '🌐' },
                        { id: 'fg-ntp', title: 'NTP', icon: '🕐' },
                        { id: 'fg-snmp', title: 'SNMP', icon: '📡' },
                        { id: 'fg-ha', title: 'High Availability', icon: '🔄' },
                        { id: 'fg-firmware', title: 'Firmware', icon: '💾' },
                        { id: 'fg-automation', title: 'Automation Stitches', icon: '🤖' },
                        { id: 'fg-fortiguard', title: 'FortiGuard', icon: '🔒' },
                    ]
                },
                {
                    id: '_fg_routing', title: 'Routing', icon: '🔀', type: 'group',
                    children: [
                        { id: 'fg-static-routes', title: 'Static Routes', icon: '📍' },
                        { id: 'fg-policy-routes', title: 'Policy Routes', icon: '🔀' },
                        { id: 'fg-bgp', title: 'BGP', icon: '🌍' },
                        { id: 'fg-ospf', title: 'OSPF', icon: '🔗' },
                        { id: 'fg-sdwan', title: 'SD-WAN', icon: '📶' },
                    ]
                },
                {
                    id: '_fg_policy', title: 'Firewall Policies', icon: '🧱', type: 'group',
                    children: [
                        { id: 'fg-policies', title: 'Firewall Policies', icon: '🧱' },
                        { id: 'fg-packet-flow', title: 'Packet Flow & Sessions', icon: '📦' },
                    ]
                },
                {
                    id: '_fg_nat', title: 'NAT', icon: '🔄', type: 'group',
                    children: [
                        { id: 'fg-nat', title: 'NAT Overview', icon: '🔄' },
                        { id: 'fg-vip', title: 'Virtual IPs (VIP)', icon: '🔄' },
                    ]
                },
                {
                    id: '_fg_objects', title: 'Objects', icon: '📁', type: 'group',
                    children: [
                        { id: 'fg-addresses', title: 'Addresses', icon: '📍' },
                        { id: 'fg-services', title: 'Services', icon: '🔧' },
                        { id: 'fg-schedules', title: 'Schedules', icon: '📅' },
                        { id: 'fg-isdb', title: 'Internet Services (ISDB)', icon: '🌍' },
                        { id: 'fg-threat-feeds', title: 'Threat Feeds', icon: '⚠️' },
                    ]
                },
                {
                    id: '_fg_security', title: 'Security Profiles', icon: '🔐', type: 'group',
                    children: [
                        { id: 'fg-antivirus', title: 'Antivirus', icon: '🦠' },
                        { id: 'fg-ips', title: 'IPS', icon: '🛡️' },
                        { id: 'fg-app-control', title: 'Application Control', icon: '📱' },
                        { id: 'fg-web-filter', title: 'Web Filter', icon: '🌐' },
                        { id: 'fg-dns-filter', title: 'DNS Filter', icon: '🔍' },
                        { id: 'fg-ssl-inspection', title: 'SSL Inspection', icon: '🔒' },
                        { id: 'fg-dos-policy', title: 'DoS Policy', icon: '💥' },
                        { id: 'fg-ztna', title: 'ZTNA', icon: '🔐' },
                        { id: 'fg-casb', title: 'CASB', icon: '☁️' },
                        { id: 'fg-sandbox', title: 'Sandbox', icon: '📦' },
                    ]
                },
                {
                    id: '_fg_vpn', title: 'VPN', icon: '🔐', type: 'group',
                    children: [
                        { id: 'fg-ssl-vpn', title: 'SSL VPN', icon: '🔒' },
                        { id: 'fg-ipsec-vpn', title: 'IPSec VPN', icon: '🔐' },
                    ]
                },
                {
                    id: '_fg_auth', title: 'Users & Authentication', icon: '👥', type: 'group',
                    children: [
                        { id: 'fg-ldap', title: 'LDAP', icon: '📂' },
                        { id: 'fg-radius', title: 'RADIUS', icon: '📡' },
                        { id: 'fg-sso', title: 'FSSO (Single Sign-On)', icon: '🔗' },
                        { id: 'fg-fortitoken', title: 'FortiToken / 2FA', icon: '🔑' },
                        { id: 'fg-saml', title: 'SAML', icon: '🎫' },
                    ]
                },
                {
                    id: '_fg_logging', title: 'Logging & Monitoring', icon: '📋', type: 'group',
                    children: [
                        { id: 'fg-logging', title: 'Logging Overview', icon: '📋' },
                        { id: 'fg-traffic-logs', title: 'Traffic Logs', icon: '📊' },
                        { id: 'fg-fortianalyzer', title: 'FortiAnalyzer', icon: '📈' },
                        { id: 'fg-security-fabric', title: 'Security Fabric', icon: '🧩' },
                    ]
                },
                {
                    id: '_fg_diag', title: 'Diagnostics & CLI', icon: '💻', type: 'group',
                    children: [
                        { id: 'fg-troubleshooting', title: 'Troubleshooting Guide', icon: '🔧' },
                        { id: 'fg-cli-reference', title: 'CLI Reference', icon: '💻' },
                        { id: 'fg-scenarios', title: 'Real-World Scenarios', icon: '🏢' },
                    ]
                },
            ]
        },
        {
            id: '_fortisiem_header', title: 'FortiSIEM', icon: '🔍', type: 'section',
            children: [
                { id: 'fsiem-overview', title: 'Overview & Architecture', icon: '🏗️' },
                { id: 'fsiem-device-management', title: 'Device Management', icon: '🖥️' },
                { id: 'fsiem-dashboard', title: 'Dashboards', icon: '📊' },
                { id: 'fsiem-event-management', title: 'Event Management', icon: '⚡' },
                { id: 'fsiem-searches', title: 'Searches (50+ Examples)', icon: '🔍' },
                { id: 'fsiem-rules', title: 'Rules & Correlation', icon: '⚙️' },
                { id: 'fsiem-reports', title: 'Reports', icon: '📄' },
                { id: 'fsiem-threat-hunting', title: 'Threat Hunting (50+ Queries)', icon: '🎯' },
                { id: 'fsiem-cmdb', title: 'CMDB', icon: '📚' },
                { id: 'fsiem-analytics', title: 'Analytics & UEBA', icon: '📊' },
                { id: 'fsiem-automation', title: 'Automation & SOAR', icon: '🤖' },
            ]
        }
    ];

    // ========================================
    // DOM ELEMENTS
    // ========================================
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    const DOM = {
        sidebar: $('#sidebar'),
        sidebarNav: $('#sidebar-nav'),
        sidebarOverlay: $('#sidebar-overlay'),
        sidebarClose: $('#sidebar-close'),
        sidebarSearchTrigger: $('#sidebar-search-trigger'),
        menuToggle: $('#menu-toggle'),
        content: $('#content'),
        toc: $('#toc'),
        tocNav: $('#toc-nav'),
        breadcrumb: $('#breadcrumb'),
        themeToggle: $('#theme-toggle'),
        printBtn: $('#print-btn'),
        searchOverlay: $('#search-overlay'),
        searchBackdrop: $('#search-backdrop'),
        searchInput: $('#search-input'),
        searchResults: $('#search-results'),
        searchTrigger: $('#search-trigger'),
        progressBar: $('#progress-bar'),
        backToTop: $('#back-to-top'),
        footerNav: $('#footer-nav'),
        logo: $('#logo'),
    };

    // ========================================
    // STATE
    // ========================================
    let currentPage = null;
    let flatPages = [];
    let searchSelectedIdx = -1;
    let scrollSpyObserver = null; // Bug 1: Track observer to disconnect on nav
    let bookmarks = JSON.parse(localStorage.getItem('kb-bookmarks') || '[]');

    // ========================================
    // INITIALIZATION
    // ========================================
    function init() {
        buildFlatPageList();
        buildSidebar();
        bindEvents();
        initTheme();
        initMermaid();
        initSidebarCollapse();

        // Load page from hash or show welcome
        const hash = window.location.hash.slice(1);
        if (hash && KB.content[hash]) {
            navigateTo(hash);
        } else {
            navigateTo('_welcome');
        }
    }

    // ========================================
    // FLAT PAGE LIST (for prev/next navigation)
    // ========================================
    function buildFlatPageList() {
        flatPages = [];
        function walk(items) {
            for (const item of items) {
                if (item.type === 'section' || item.type === 'group') {
                    if (item.children) walk(item.children);
                } else {
                    flatPages.push(item);
                }
            }
        }
        walk(NAV_TREE);
    }

    // ========================================
    // SIDEBAR NAVIGATION
    // ========================================
    function buildSidebar() {
        DOM.sidebarNav.innerHTML = '';
        NAV_TREE.forEach(item => {
            DOM.sidebarNav.appendChild(createNavElement(item));
        });
    }

    function createNavElement(item) {
        if (item.type === 'section') {
            const section = document.createElement('div');
            section.className = 'nav-section';

            const title = document.createElement('div');
            title.className = 'nav-section-title';
            title.innerHTML = `<span>${item.icon || ''}</span> ${item.title}`;
            section.appendChild(title);

            if (item.children) {
                item.children.forEach(child => {
                    section.appendChild(createNavElement(child));
                });
            }
            return section;
        }

        if (item.type === 'group') {
            const group = document.createElement('div');
            group.className = 'nav-group';

            const toggle = document.createElement('button');
            toggle.className = 'nav-group-toggle';
            toggle.innerHTML = `
                <span class="nav-icon">${item.icon || ''}</span>
                <span class="nav-label">${item.title}</span>
                <span class="nav-chevron">▸</span>
            `;

            const children = document.createElement('div');
            children.className = 'nav-group-children';

            if (item.children) {
                item.children.forEach(child => {
                    children.appendChild(createNavElement(child));
                });
            }

            toggle.addEventListener('click', () => {
                toggle.classList.toggle('expanded');
                children.classList.toggle('expanded');
            });

            group.appendChild(toggle);
            group.appendChild(children);
            return group;
        }

        // Regular page item
        const el = document.createElement('div');
        el.className = 'nav-item';
        el.dataset.page = item.id;
        el.innerHTML = `
            <span class="nav-icon">${item.icon || '📄'}</span>
            <span class="nav-label">${item.title}</span>
        `;
        el.addEventListener('click', () => navigateTo(item.id));
        return el;
    }

    // ========================================
    // NAVIGATION
    // ========================================
    function navigateTo(pageId) {
        // Get content
        let html = KB.content[pageId];
        if (!html && pageId === '_welcome') {
            html = getWelcomeContent();
        }
        if (!html) {
            html = getPlaceholderContent(pageId);
        }

        // Bug 5: Re-trigger fade animation on navigate
        DOM.content.classList.remove('content-animate');
        // Force reflow to restart animation
        void DOM.content.offsetWidth;
        DOM.content.classList.add('content-animate');

        // Render
        DOM.content.innerHTML = html;
        currentPage = pageId;

        // Update URL hash
        window.location.hash = pageId;

        // Update sidebar active state
        $$('.nav-item').forEach(el => el.classList.remove('active'));
        const activeItem = $(`.nav-item[data-page="${pageId}"]`);
        if (activeItem) {
            activeItem.classList.add('active');
            // Expand parent group if collapsed
            const parentGroup = activeItem.closest('.nav-group-children');
            if (parentGroup && !parentGroup.classList.contains('expanded')) {
                parentGroup.classList.add('expanded');
                const toggle = parentGroup.previousElementSibling;
                if (toggle) toggle.classList.add('expanded');
            }
        }

        // Update breadcrumb
        updateBreadcrumb(pageId);

        // Update TOC
        updateTOC();

        // Update footer nav (prev/next)
        updateFooterNav(pageId);

        // Initialize features in new content
        initCodeCopyButtons();
        initTabs();
        renderMermaid();
        insertReadingTime();
        insertBookmarkButton();

        // Scroll to top
        DOM.content.scrollTop = 0;
        window.scrollTo({ top: 0 });

        // Close mobile sidebar
        closeMobileSidebar();
    }

    function updateBreadcrumb(pageId) {
        const parts = [];

        function find(items, parents) {
            for (const item of items) {
                const path = [...parents, item];
                if (item.id === pageId) {
                    return path;
                }
                if (item.children) {
                    const result = find(item.children, path);
                    if (result) return result;
                }
            }
            return null;
        }

        const path = find(NAV_TREE, []) || [];
        DOM.breadcrumb.innerHTML = path.map((p, i) => {
            const isLast = i === path.length - 1;
            const sep = i > 0 ? '<span class="breadcrumb-sep">›</span>' : '';
            const cls = isLast ? 'breadcrumb-item' : 'breadcrumb-item clickable';
            return `${sep}<span class="${cls}" data-page="${p.id}">${p.title}</span>`;
        }).join('');

        // Bug 2: Bind click on breadcrumb items via delegation
        DOM.breadcrumb.querySelectorAll('.breadcrumb-item.clickable').forEach(el => {
            el.addEventListener('click', () => {
                const targetId = el.dataset.page;
                // For section/group IDs (prefixed with _), navigate to first child page
                const firstChild = findFirstChildPage(targetId);
                if (firstChild) {
                    navigateTo(firstChild);
                }
            });
        });
    }

    // Bug 2: Helper to find first navigable child page of a section/group
    function findFirstChildPage(groupId) {
        function walk(items) {
            for (const item of items) {
                if (item.id === groupId && item.children) {
                    return getFirstPage(item.children);
                }
                if (item.children) {
                    const result = walk(item.children);
                    if (result) return result;
                }
            }
            return null;
        }
        function getFirstPage(items) {
            for (const item of items) {
                if (!item.type || item.type === 'page') return item.id;
                if (item.children) {
                    const result = getFirstPage(item.children);
                    if (result) return result;
                }
            }
            return null;
        }
        return walk(NAV_TREE);
    }

    // ========================================
    // TABLE OF CONTENTS
    // ========================================
    function updateTOC() {
        const headings = DOM.content.querySelectorAll('h2, h3, h4');
        if (headings.length < 2) {
            DOM.toc.classList.remove('visible');
            return;
        }

        DOM.toc.classList.add('visible');
        DOM.tocNav.innerHTML = '';

        headings.forEach((heading, idx) => {
            const id = heading.id || `heading-${idx}`;
            heading.id = id;

            const link = document.createElement('a');
            link.href = `#${id}`;
            link.textContent = heading.textContent;
            link.className = `toc-${heading.tagName.toLowerCase()}`;
            link.addEventListener('click', (e) => {
                e.preventDefault();
                heading.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
            DOM.tocNav.appendChild(link);
        });

        // Scroll spy
        initScrollSpy(headings);
    }

    function initScrollSpy(headings) {
        // Bug 1: Disconnect previous observer to prevent memory leak
        if (scrollSpyObserver) {
            scrollSpyObserver.disconnect();
            scrollSpyObserver = null;
        }

        scrollSpyObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const id = entry.target.id;
                    DOM.tocNav.querySelectorAll('a').forEach(a => {
                        a.classList.toggle('active', a.getAttribute('href') === `#${id}`);
                    });
                }
            });
        }, {
            rootMargin: '-80px 0px -70% 0px',
            threshold: 0
        });

        headings.forEach(h => scrollSpyObserver.observe(h));
    }

    // ========================================
    // FOOTER NAVIGATION (Prev / Next)
    // ========================================
    function updateFooterNav(pageId) {
        const idx = flatPages.findIndex(p => p.id === pageId);
        let html = '';

        if (idx > 0) {
            const prev = flatPages[idx - 1];
            html += `<button class="footer-nav-btn prev" data-page="${prev.id}">
                <span class="footer-nav-label">← Previous</span>
                <span class="footer-nav-title">${prev.title}</span>
            </button>`;
        }

        if (idx < flatPages.length - 1 && idx >= 0) {
            const next = flatPages[idx + 1];
            html += `<button class="footer-nav-btn next" data-page="${next.id}">
                <span class="footer-nav-label">Next →</span>
                <span class="footer-nav-title">${next.title}</span>
            </button>`;
        }

        DOM.footerNav.innerHTML = html;
        DOM.footerNav.querySelectorAll('.footer-nav-btn').forEach(btn => {
            btn.addEventListener('click', () => navigateTo(btn.dataset.page));
        });
    }

    // ========================================
    // CODE COPY BUTTONS
    // ========================================
    function initCodeCopyButtons() {
        DOM.content.querySelectorAll('.code-copy-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const code = btn.closest('.code-block').querySelector('code');
                if (code) {
                    navigator.clipboard.writeText(code.textContent).then(() => {
                        btn.textContent = 'Copied!';
                        btn.classList.add('copied');
                        setTimeout(() => {
                            btn.textContent = 'Copy';
                            btn.classList.remove('copied');
                        }, 2000);
                    });
                }
            });
        });
    }

    // ========================================
    // TABS
    // ========================================
    function initTabs() {
        DOM.content.querySelectorAll('.tabs').forEach(tabContainer => {
            const buttons = tabContainer.querySelectorAll('.tab-btn');
            const contents = tabContainer.querySelectorAll('.tab-content');

            buttons.forEach(btn => {
                btn.addEventListener('click', () => {
                    const target = btn.dataset.tab;
                    buttons.forEach(b => b.classList.remove('active'));
                    contents.forEach(c => c.classList.remove('active'));
                    btn.classList.add('active');
                    const targetContent = tabContainer.querySelector(`.tab-content[data-tab="${target}"]`);
                    if (targetContent) targetContent.classList.add('active');
                });
            });
        });
    }

    // ========================================
    // MERMAID
    // ========================================
    function initMermaid() {
        if (typeof mermaid !== 'undefined') {
            mermaid.initialize({
                startOnLoad: false,
                theme: document.documentElement.dataset.theme === 'dark' ? 'dark' : 'default',
                securityLevel: 'loose',
                flowchart: { useMaxWidth: true, htmlLabels: true },
                themeVariables: {
                    primaryColor: '#1e293b',
                    primaryTextColor: '#e2e8f0',
                    primaryBorderColor: '#334155',
                    lineColor: '#64748b',
                    secondaryColor: '#1a2035',
                    tertiaryColor: '#0f1629'
                }
            });
        }
    }

    function renderMermaid() {
        if (typeof mermaid === 'undefined') return;
        const charts = DOM.content.querySelectorAll('.mermaid');
        if (charts.length === 0) return;

        charts.forEach((el, i) => {
            const id = `mermaid-${Date.now()}-${i}`;
            try {
                mermaid.render(id, el.textContent).then(result => {
                    el.innerHTML = result.svg;
                }).catch(err => {
                    console.warn('Mermaid render error:', err);
                    el.innerHTML = `<div style="color: var(--warning); font-size: 0.85em;">Diagram render error. Check syntax.</div>`;
                });
            } catch (err) {
                console.warn('Mermaid error:', err);
            }
        });
    }

    // ========================================
    // SEARCH
    // ========================================
    function openSearch() {
        DOM.searchOverlay.classList.add('active');
        DOM.searchInput.value = '';
        DOM.searchInput.focus();
        searchSelectedIdx = -1;
        showSearchEmpty();
    }

    function closeSearch() {
        DOM.searchOverlay.classList.remove('active');
        DOM.searchInput.value = '';
        searchSelectedIdx = -1;
    }

    function showSearchEmpty() {
        DOM.searchResults.innerHTML = `
            <div class="search-empty">
                <p>Type to search across all documentation...</p>
                <div class="search-tips">
                    <span><kbd>↑</kbd><kbd>↓</kbd> Navigate</span>
                    <span><kbd>↵</kbd> Open</span>
                    <span><kbd>ESC</kbd> Close</span>
                </div>
            </div>
        `;
    }

    function performSearch(query) {
        if (!query || query.length < 2) {
            showSearchEmpty();
            return;
        }

        const q = query.toLowerCase();
        const results = [];

        // Search in all registered content
        for (const [id, html] of Object.entries(KB.content)) {
            // Strip HTML to get text
            const text = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
            const textLower = text.toLowerCase();
            const idx = textLower.indexOf(q);

            if (idx !== -1) {
                // Extract page title from first h1
                const titleMatch = html.match(/<h1[^>]*>(.*?)<\/h1>/);
                const title = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, '') : id;

                // Get surrounding snippet
                const start = Math.max(0, idx - 60);
                const end = Math.min(text.length, idx + query.length + 60);
                let snippet = text.substring(start, end).trim();
                if (start > 0) snippet = '...' + snippet;
                if (end < text.length) snippet += '...';

                // Find section path
                const path = findPagePath(id);

                results.push({
                    id,
                    title,
                    path,
                    snippet,
                    relevance: titleMatch && titleMatch[1].toLowerCase().includes(q) ? 2 : 1
                });
            }
        }

        // Sort by relevance
        results.sort((a, b) => b.relevance - a.relevance);

        if (results.length === 0) {
            DOM.searchResults.innerHTML = `
                <div class="search-no-results">
                    <div class="noresults-icon">🔍</div>
                    <p>No results found for "<strong>${escapeHtml(query)}</strong>"</p>
                    <p style="margin-top: 8px; font-size: 12px; color: var(--text-muted);">Try different keywords or check spelling</p>
                </div>
            `;
            return;
        }

        searchSelectedIdx = 0;

        DOM.searchResults.innerHTML = results.slice(0, 20).map((r, i) => {
            // Bug 6: Escape snippet FIRST, then highlight
            const escapedSnippet = escapeHtml(r.snippet);
            const highlightedSnippet = escapedSnippet.replace(
                new RegExp(`(${escapeRegex(escapeHtml(query))})`, 'gi'),
                '<mark>$1</mark>'
            );
            return `
                <div class="search-result-item${i === 0 ? ' selected' : ''}" data-page="${r.id}" data-idx="${i}">
                    <span class="search-result-title">${escapeHtml(r.title)}</span>
                    <span class="search-result-path">${escapeHtml(r.path)}</span>
                    <span class="search-result-snippet">${highlightedSnippet}</span>
                </div>
            `;
        }).join('');

        // Bind clicks
        DOM.searchResults.querySelectorAll('.search-result-item').forEach(item => {
            item.addEventListener('click', () => {
                navigateTo(item.dataset.page);
                closeSearch();
            });
        });
    }

    function findPagePath(pageId) {
        function walk(items, parents) {
            for (const item of items) {
                if (item.id === pageId) return [...parents, item.title].join(' > ');
                if (item.children) {
                    const result = walk(item.children, [...parents, item.title]);
                    if (result) return result;
                }
            }
            return null;
        }
        return walk(NAV_TREE, []) || pageId;
    }

    // ========================================
    // THEME
    // ========================================
    function initTheme() {
        const saved = localStorage.getItem('kb-theme');
        const pref = saved || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
        document.documentElement.dataset.theme = pref;
    }

    function toggleTheme() {
        const current = document.documentElement.dataset.theme;
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.dataset.theme = next;
        localStorage.setItem('kb-theme', next);
        // Bug 3: Re-initialize AND re-render mermaid with new theme
        initMermaid();
        renderMermaid();
    }

    // ========================================
    // MOBILE SIDEBAR
    // ========================================
    function openMobileSidebar() {
        DOM.sidebar.classList.add('open');
        DOM.sidebarOverlay.classList.add('active');
        document.body.style.overflow = 'hidden';
    }

    function closeMobileSidebar() {
        DOM.sidebar.classList.remove('open');
        DOM.sidebarOverlay.classList.remove('active');
        document.body.style.overflow = '';
    }

    // ========================================
    // PROGRESS BAR
    // ========================================
    function updateProgressBar() {
        const scrollTop = window.scrollY;
        const docHeight = document.documentElement.scrollHeight - window.innerHeight;
        const progress = docHeight > 0 ? (scrollTop / docHeight) * 100 : 0;
        DOM.progressBar.style.width = `${progress}%`;
    }

    // ========================================
    // BACK TO TOP
    // ========================================
    function updateBackToTop() {
        DOM.backToTop.classList.toggle('visible', window.scrollY > 400);
    }

    // ========================================
    // EVENT BINDINGS
    // ========================================
    function bindEvents() {
        // Theme toggle
        DOM.themeToggle.addEventListener('click', toggleTheme);

        // Print
        DOM.printBtn.addEventListener('click', () => window.print());

        // Mobile sidebar
        DOM.menuToggle.addEventListener('click', openMobileSidebar);
        DOM.sidebarClose.addEventListener('click', closeMobileSidebar);
        DOM.sidebarOverlay.addEventListener('click', closeMobileSidebar);

        // Search
        DOM.sidebarSearchTrigger.addEventListener('click', openSearch);
        DOM.searchTrigger.addEventListener('click', openSearch);
        DOM.searchBackdrop.addEventListener('click', closeSearch);

        DOM.searchInput.addEventListener('input', (e) => {
            performSearch(e.target.value);
        });

        // Bug 4: Removed duplicate Escape handler — global handler covers it
        DOM.searchInput.addEventListener('keydown', (e) => {
            const items = DOM.searchResults.querySelectorAll('.search-result-item');
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (searchSelectedIdx < items.length - 1) {
                    searchSelectedIdx++;
                    items.forEach((item, i) => item.classList.toggle('selected', i === searchSelectedIdx));
                    items[searchSelectedIdx]?.scrollIntoView({ block: 'nearest' });
                }
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (searchSelectedIdx > 0) {
                    searchSelectedIdx--;
                    items.forEach((item, i) => item.classList.toggle('selected', i === searchSelectedIdx));
                    items[searchSelectedIdx]?.scrollIntoView({ block: 'nearest' });
                }
            } else if (e.key === 'Enter') {
                e.preventDefault();
                const selected = items[searchSelectedIdx];
                if (selected) {
                    navigateTo(selected.dataset.page);
                    closeSearch();
                }
            }
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                openSearch();
                return;
            }
            if (e.key === 'Escape') {
                if (DOM.searchOverlay.classList.contains('active')) {
                    closeSearch();
                    return;
                }
                const shortcutsPanel = $('#shortcuts-overlay');
                if (shortcutsPanel && shortcutsPanel.classList.contains('active')) {
                    closeShortcutsPanel();
                    return;
                }
            }
            // Feature 1: Open shortcuts panel with '?'
            if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) {
                const tag = document.activeElement?.tagName;
                if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
                e.preventDefault();
                openShortcutsPanel();
                return;
            }
            // Keyboard nav: left/right arrow for prev/next page
            if (e.key === 'ArrowLeft' && e.altKey) {
                e.preventDefault();
                navigatePrevNext(-1);
            }
            if (e.key === 'ArrowRight' && e.altKey) {
                e.preventDefault();
                navigatePrevNext(1);
            }
        });

        // Scroll events
        window.addEventListener('scroll', () => {
            updateProgressBar();
            updateBackToTop();
        }, { passive: true });

        // Back to top
        DOM.backToTop.addEventListener('click', () => {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });

        // Hash change
        window.addEventListener('hashchange', () => {
            const hash = window.location.hash.slice(1);
            if (hash && hash !== currentPage && (KB.content[hash] || hash === '_welcome')) {
                navigateTo(hash);
            }
        });

        // Logo click
        DOM.logo.addEventListener('click', () => navigateTo('_welcome'));

        // Feature 3: Sidebar collapse toggle
        const collapseBtn = $('#sidebar-collapse');
        if (collapseBtn) {
            collapseBtn.addEventListener('click', toggleSidebarCollapse);
        }
    }

    // ========================================
    // KEYBOARD PREV/NEXT NAVIGATION
    // ========================================
    function navigatePrevNext(direction) {
        const idx = flatPages.findIndex(p => p.id === currentPage);
        const nextIdx = idx + direction;
        if (nextIdx >= 0 && nextIdx < flatPages.length) {
            navigateTo(flatPages[nextIdx].id);
        }
    }

    // ========================================
    // FEATURE 1: KEYBOARD SHORTCUTS PANEL
    // ========================================
    function openShortcutsPanel() {
        const overlay = $('#shortcuts-overlay');
        if (overlay) {
            overlay.classList.add('active');
        }
    }

    function closeShortcutsPanel() {
        const overlay = $('#shortcuts-overlay');
        if (overlay) {
            overlay.classList.remove('active');
        }
    }

    // ========================================
    // FEATURE 2: READING TIME ESTIMATE
    // ========================================
    function insertReadingTime() {
        const h1 = DOM.content.querySelector('h1');
        if (!h1 || currentPage === '_welcome') return;

        // Get text content and count words
        const text = DOM.content.textContent || '';
        const words = text.trim().split(/\s+/).filter(w => w.length > 0).length;
        const readingTime = Math.max(1, Math.ceil(words / 200));

        // Count code blocks
        const codeBlocks = DOM.content.querySelectorAll('.code-block').length;

        const badge = document.createElement('div');
        badge.className = 'reading-time-badge';
        badge.innerHTML = `
            <span class="reading-time-icon">📖</span>
            <span>${readingTime} min read</span>
            <span class="reading-time-sep">·</span>
            <span>${words.toLocaleString()} words</span>
            ${codeBlocks > 0 ? `<span class="reading-time-sep">·</span><span>${codeBlocks} code block${codeBlocks > 1 ? 's' : ''}</span>` : ''}
        `;

        h1.insertAdjacentElement('afterend', badge);
    }

    // ========================================
    // FEATURE 3: COLLAPSIBLE SIDEBAR
    // ========================================
    function initSidebarCollapse() {
        const collapsed = localStorage.getItem('kb-sidebar-collapsed') === 'true';
        if (collapsed) {
            DOM.sidebar.classList.add('sidebar-collapsed');
            const mainEl = $('#main');
            if (mainEl) mainEl.classList.add('sidebar-is-collapsed');
        }
    }

    function toggleSidebarCollapse() {
        DOM.sidebar.classList.toggle('sidebar-collapsed');
        const mainEl = $('#main');
        if (mainEl) mainEl.classList.toggle('sidebar-is-collapsed');
        const isCollapsed = DOM.sidebar.classList.contains('sidebar-collapsed');
        localStorage.setItem('kb-sidebar-collapsed', isCollapsed);
    }

    // ========================================
    // FEATURE 4: BOOKMARK / FAVORITES SYSTEM
    // ========================================
    function toggleBookmark(pageId) {
        const idx = bookmarks.indexOf(pageId);
        if (idx === -1) {
            bookmarks.push(pageId);
        } else {
            bookmarks.splice(idx, 1);
        }
        localStorage.setItem('kb-bookmarks', JSON.stringify(bookmarks));
        renderBookmarksSidebar();
        updateBookmarkButton();
    }

    function insertBookmarkButton() {
        const h1 = DOM.content.querySelector('h1');
        if (!h1 || currentPage === '_welcome') return;

        const isBookmarked = bookmarks.includes(currentPage);
        const btn = document.createElement('button');
        btn.className = `bookmark-btn${isBookmarked ? ' bookmarked' : ''}`;
        btn.id = 'bookmark-btn';
        btn.title = isBookmarked ? 'Remove bookmark' : 'Bookmark this page';
        btn.setAttribute('aria-label', btn.title);
        btn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="${isBookmarked ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>`;
        btn.addEventListener('click', () => {
            toggleBookmark(currentPage);
        });

        h1.style.position = 'relative';
        h1.appendChild(btn);
    }

    function updateBookmarkButton() {
        const btn = $('#bookmark-btn');
        if (!btn) return;
        const isBookmarked = bookmarks.includes(currentPage);
        btn.classList.toggle('bookmarked', isBookmarked);
        btn.title = isBookmarked ? 'Remove bookmark' : 'Bookmark this page';
        btn.querySelector('svg').setAttribute('fill', isBookmarked ? 'currentColor' : 'none');
    }

    function renderBookmarksSidebar() {
        // Remove existing bookmarks section
        const existing = DOM.sidebarNav.querySelector('.bookmarks-section');
        if (existing) existing.remove();

        if (bookmarks.length === 0) return;

        const section = document.createElement('div');
        section.className = 'bookmarks-section';

        const title = document.createElement('div');
        title.className = 'nav-section-title';
        title.innerHTML = '<span>⭐</span> Bookmarks';
        section.appendChild(title);

        bookmarks.forEach(pageId => {
            const page = flatPages.find(p => p.id === pageId);
            if (!page) return;
            const el = document.createElement('div');
            el.className = 'nav-item bookmark-item';
            el.dataset.page = pageId;
            el.innerHTML = `
                <span class="nav-icon">${page.icon || '📄'}</span>
                <span class="nav-label">${page.title}</span>
                <button class="bookmark-remove" title="Remove bookmark" aria-label="Remove bookmark">×</button>
            `;
            el.addEventListener('click', (e) => {
                if (e.target.closest('.bookmark-remove')) {
                    e.stopPropagation();
                    toggleBookmark(pageId);
                    return;
                }
                navigateTo(pageId);
            });
            section.appendChild(el);
        });

        DOM.sidebarNav.prepend(section);
    }

    // ========================================
    // WELCOME PAGE CONTENT
    // ========================================
    function getWelcomeContent() {
        return `
            <div class="welcome-hero">
                <h1>🛡️ Fortinet Knowledge Base</h1>
                <p class="hero-subtitle">
                    Enterprise-grade reference documentation for FortiGate Firewall and FortiSIEM.
                    Built for security engineers, SOC analysts, and network administrators.
                </p>
            </div>

            <div class="welcome-stats">
                <div class="welcome-stat">
                    <div class="welcome-stat-value">${Object.keys(KB.content).length}+</div>
                    <div class="welcome-stat-label">Documentation Pages</div>
                </div>
                <div class="welcome-stat">
                    <div class="welcome-stat-value">500+</div>
                    <div class="welcome-stat-label">CLI Commands</div>
                </div>
                <div class="welcome-stat">
                    <div class="welcome-stat-value">100+</div>
                    <div class="welcome-stat-label">Hunting Queries</div>
                </div>
                <div class="welcome-stat">
                    <div class="welcome-stat-value">200+</div>
                    <div class="welcome-stat-label">Search Examples</div>
                </div>
            </div>

            <div class="welcome-cards">
                <div class="welcome-card" onclick="window.location.hash='fg-dashboard'">
                    <div class="welcome-card-icon">🛡️</div>
                    <h3>FortiGate Firewall</h3>
                    <p>Complete coverage of every GUI menu, firewall policies, NAT, VPN, routing, security profiles, diagnostics, and CLI commands.</p>
                </div>
                <div class="welcome-card" onclick="window.location.hash='fsiem-overview'">
                    <div class="welcome-card-icon">🔍</div>
                    <h3>FortiSIEM</h3>
                    <p>Architecture, event parsing, advanced search with 100+ examples, correlation rules, incident management, and SOC operations.</p>
                </div>
                <div class="welcome-card" onclick="window.location.hash='fg-policies'">
                    <div class="welcome-card-icon">🧱</div>
                    <h3>Firewall Policies</h3>
                    <p>Deep dive into policy anatomy, packet flow, session tables, policy diagnostics, shadow policies, and best practices.</p>
                </div>
                <div class="welcome-card" onclick="window.location.hash='fg-troubleshooting'">
                    <div class="welcome-card-icon">🔧</div>
                    <h3>Troubleshooting</h3>
                    <p>Systematic troubleshooting guides with debug commands, packet captures, expected outputs, and root cause analysis.</p>
                </div>
                <div class="welcome-card" onclick="window.location.hash='fsiem-threat-hunting'">
                    <div class="welcome-card-icon">🎣</div>
                    <h3>Threat Hunting</h3>
                    <p>100 practical hunting queries with explanations, MITRE ATT&CK mapping, and investigation workflows.</p>
                </div>
                <div class="welcome-card" onclick="window.location.hash='fg-scenarios'">
                    <div class="welcome-card-icon">🏢</div>
                    <h3>Real-World Scenarios</h3>
                    <p>Enterprise deployment scenarios including DMZ, VPN, segmentation, guest networks, and voice VLANs.</p>
                </div>
            </div>

            <div class="callout tip">
                <div class="callout-title">💡 Quick Navigation</div>
                <p>Use <kbd>Ctrl</kbd> + <kbd>K</kbd> to open the search dialog. Navigate the sidebar to browse topics. Each page includes CLI equivalents, GUI paths, best practices, and troubleshooting steps.</p>
            </div>

            <h2 id="coverage">What's Covered</h2>

            <div class="two-col">
                <div>
                    <h4>FortiGate Firewall</h4>
                    <ul>
                        <li>Every GUI page documented</li>
                        <li>Complete CLI reference</li>
                        <li>Firewall policies deep dive</li>
                        <li>Security profiles (AV, IPS, WAF, etc.)</li>
                        <li>NAT (SNAT, DNAT, VIP, Hairpin)</li>
                        <li>VPN (SSL VPN, IPSec, IKEv1/v2)</li>
                        <li>Routing (Static, BGP, OSPF, SD-WAN)</li>
                        <li>Authentication (LDAP, RADIUS, SSO, SAML)</li>
                        <li>HA, VDOM, diagnostics</li>
                        <li>Packet flow with diagrams</li>
                        <li>Enterprise scenarios & labs</li>
                    </ul>
                </div>
                <div>
                    <h4>FortiSIEM</h4>
                    <ul>
                        <li>Architecture & deployment</li>
                        <li>Device discovery & CMDB</li>
                        <li>Event parsing & normalization</li>
                        <li>Advanced search (100+ examples)</li>
                        <li>Correlation rules & MITRE mapping</li>
                        <li>Incident management & playbooks</li>
                        <li>Dashboards & reports</li>
                        <li>Threat intelligence & IOCs</li>
                        <li>SOC operations & triage</li>
                        <li>100 hunting queries</li>
                        <li>Troubleshooting & performance</li>
                    </ul>
                </div>
            </div>
        `;
    }

    // ========================================
    // PLACEHOLDER CONTENT
    // ========================================
    function getPlaceholderContent(pageId) {
        const item = flatPages.find(p => p.id === pageId);
        const title = item ? item.title : pageId;
        return `
            <h1>${item ? item.icon + ' ' : ''}${title}</h1>
            <div class="callout info">
                <div class="callout-title">ℹ️ Content Loading</div>
                <p>This section is being loaded. If you see this message, the content module for <code>${pageId}</code> may still be loading or is not yet available.</p>
            </div>
        `;
    }

    // ========================================
    // UTILITY FUNCTIONS
    // ========================================
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function escapeRegex(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    // ========================================
    // BOOT
    // ========================================
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            init();
            renderBookmarksSidebar();
            // Bind shortcuts panel backdrop
            const shortcutsBackdrop = $('#shortcuts-backdrop');
            if (shortcutsBackdrop) shortcutsBackdrop.addEventListener('click', closeShortcutsPanel);
        });
    } else {
        init();
        renderBookmarksSidebar();
        const shortcutsBackdrop = $('#shortcuts-backdrop');
        if (shortcutsBackdrop) shortcutsBackdrop.addEventListener('click', closeShortcutsPanel);
    }

})();
