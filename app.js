/**
 * ==============================================================================
 * AEGIS-VAULT : PRIMARY APPLICATION CONTROLLER & UI LOGIC
 * ==============================================================================
 * Course / Topic : Cryptography and Network Security (CNS)
 * Architecture   : Zero-Knowledge Client Controller
 * ==============================================================================
 */

(function () {
    'use strict';

    // Application State
    const state = {
        unlocked: false,
        masterPassword: '',
        vaultEnvelope: null,
        items: [],
        filteredCategory: 'all',
        searchQuery: '',
        autoLockInterval: null,
        autoLockSecondsRemaining: 300, // 5 minutes
        clipboardTimeout: null,
        activeTab: 'tab-vault',
        currentAesRound: 1,
        aesTraceData: null
    };

    // Storage Key
    const STORAGE_KEY = 'aegis_vault_envelope_v2';

    // Demo CNS Academic Seed Data
    const DEMO_ITEMS = [
        {
            id: 'demo-1',
            title: 'GitHub Enterprise Security Admin',
            category: 'login',
            username: 'sec_admin@infosec.corp',
            password: 'G!tHub#Pr0t0c0l$99xK!',
            url: 'https://github.com',
            notes: 'FIDO2 Hardware WebAuthn key primary; 2FA backup codes in safe.',
            favorite: true,
            createdAt: new Date(Date.now() - 15 * 86400000).toISOString(),
            updatedAt: new Date(Date.now() - 15 * 86400000).toISOString(),
            history: []
        },
        {
            id: 'demo-2',
            title: 'AWS Cloud Production IAM Key',
            category: 'api',
            username: 'AKIAIOSFODNN7EXAMPLE',
            password: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            url: 'https://aws.amazon.com',
            notes: 'Root account access restricted. CloudTrail audit logging enabled.',
            favorite: true,
            createdAt: new Date(Date.now() - 40 * 86400000).toISOString(),
            updatedAt: new Date(Date.now() - 40 * 86400000).toISOString(),
            history: []
        },
        {
            id: 'demo-3',
            title: 'University CNS Academic Portal',
            category: 'login',
            username: 'student_cns_2026',
            password: 'Password123!', // Intentionally weak to demo audit alert
            url: 'https://portal.university.edu',
            notes: 'Cryptography and Network Security project submission link.',
            favorite: false,
            createdAt: new Date(Date.now() - 120 * 86400000).toISOString(), // Stale > 90 days
            updatedAt: new Date(Date.now() - 120 * 86400000).toISOString(),
            history: []
        },
        {
            id: 'demo-4',
            title: 'Corporate Expense Corporate Card',
            category: 'card',
            username: 'Cardholder: Md Sairin Saidat',
            password: '4532-8921-3310-9844 | CVV: 712 | Exp: 09/29',
            url: '',
            notes: '3D Secure 2.0 biometric authorization active.',
            favorite: false,
            createdAt: new Date(Date.now() - 2 * 86400000).toISOString(),
            updatedAt: new Date(Date.now() - 2 * 86400000).toISOString(),
            history: []
        },
        {
            id: 'demo-5',
            title: 'Bitcoin Hardware Wallet Recovery Seed',
            category: 'note',
            username: 'Cold Storage Ledger Nano X',
            password: 'matrix cipher galaxy shield quantum sentinel vector horizon nebula protocol zenith glacier',
            url: '',
            notes: 'BIP-39 12-word seed phrase for cold storage vault.',
            favorite: true,
            createdAt: new Date(Date.now() - 60 * 86400000).toISOString(),
            updatedAt: new Date(Date.now() - 60 * 86400000).toISOString(),
            history: []
        }
    ];

    /* ==========================================================================
     * 1. INITIALIZATION & DOM CACHE
     * ========================================================================== */
    const dom = {};

    function cacheDom() {
        // Navigation & Status
        dom.navTabs = document.querySelectorAll('.tab-btn');
        dom.tabPanels = document.querySelectorAll('.tab-panel');
        dom.statusDot = document.getElementById('statusDot');
        dom.statusText = document.getElementById('statusText');
        dom.autoLockTimer = document.getElementById('autoLockTimer');
        dom.btnLockVault = document.getElementById('btnLockVault');

        // Master Lock Overlay
        dom.lockScreenOverlay = document.getElementById('lockScreenOverlay');
        dom.masterPasswordInput = document.getElementById('masterPasswordInput');
        dom.btnToggleMasterVis = document.getElementById('btnToggleMasterVis');
        dom.masterStrengthFill = document.getElementById('masterStrengthFill');
        dom.masterStrengthLabel = document.getElementById('masterStrengthLabel');
        dom.btnUnlockVault = document.getElementById('btnUnlockVault');
        dom.btnLoadDemoDataset = document.getElementById('btnLoadDemoDataset');

        // Vault View
        dom.vaultItemsGrid = document.getElementById('vaultItemsGrid');
        dom.vaultSearchInput = document.getElementById('vaultSearchInput');
        dom.categoryFilterContainer = document.getElementById('categoryFilterContainer');
        dom.statTotalItems = document.getElementById('statTotalItems');
        dom.statHealthScore = document.getElementById('statHealthScore');
        dom.btnAddNewItem = document.getElementById('btnAddNewItem');
        dom.btnExportVault = document.getElementById('btnExportVault');
        dom.btnImportVault = document.getElementById('btnImportVault');
        dom.fileVaultImport = document.getElementById('fileVaultImport');

        // Add/Edit Modal
        dom.itemModalOverlay = document.getElementById('itemModalOverlay');
        dom.btnCloseItemModal = document.getElementById('btnCloseItemModal');
        dom.btnCancelItemModal = document.getElementById('btnCancelItemModal');
        dom.vaultItemForm = document.getElementById('vaultItemForm');
        dom.itemModalTitle = document.getElementById('itemModalTitle');
        dom.itemIdField = document.getElementById('itemIdField');
        dom.itemCategoryField = document.getElementById('itemCategoryField');
        dom.itemTitleField = document.getElementById('itemTitleField');
        dom.itemUsernameField = document.getElementById('itemUsernameField');
        dom.itemPasswordField = document.getElementById('itemPasswordField');
        dom.itemUrlField = document.getElementById('itemUrlField');
        dom.itemNotesField = document.getElementById('itemNotesField');
        dom.btnGenPasswordForModal = document.getElementById('btnGenPasswordForModal');
        dom.modalPasswordEntropyFill = document.getElementById('modalPasswordEntropyFill');
        dom.modalPasswordEntropyLabel = document.getElementById('modalPasswordEntropyLabel');

        // Generator & Entropy Tab
        dom.generatedPasswordDisplay = document.getElementById('generatedPasswordDisplay');
        dom.genEntropyBadge = document.getElementById('genEntropyBadge');
        dom.btnRegeneratePassword = document.getElementById('btnRegeneratePassword');
        dom.btnCopyGeneratedPassword = document.getElementById('btnCopyGeneratedPassword');
        dom.modeRandomChars = document.getElementById('modeRandomChars');
        dom.modeDiceware = document.getElementById('modeDiceware');
        dom.lengthControlRow = document.getElementById('lengthControlRow');
        dom.wordsControlRow = document.getElementById('wordsControlRow');
        dom.genLengthSlider = document.getElementById('genLengthSlider');
        dom.genLengthVal = document.getElementById('genLengthVal');
        dom.genWordsSlider = document.getElementById('genWordsSlider');
        dom.genWordsVal = document.getElementById('genWordsVal');
        dom.chkUpper = document.getElementById('chkUpper');
        dom.chkLower = document.getElementById('chkLower');
        dom.chkDigits = document.getElementById('chkDigits');
        dom.chkSymbols = document.getElementById('chkSymbols');
        dom.chkAvoidAmbiguous = document.getElementById('chkAvoidAmbiguous');
        dom.entropyNumberDisplay = document.getElementById('entropyNumberDisplay');
        dom.entropyRatingDisplay = document.getElementById('entropyRatingDisplay');
        dom.entropyMeterFill = document.getElementById('entropyMeterFill');
        dom.crackTimeOnline = document.getElementById('crackTimeOnline');
        dom.crackTimeFastGpu = document.getElementById('crackTimeFastGpu');
        dom.crackTimeCluster = document.getElementById('crackTimeCluster');
        dom.crackTimeQuantum = document.getElementById('crackTimeQuantum');

        // Audit Tab
        dom.auditScoreVal = document.getElementById('auditScoreVal');
        dom.auditWeakCount = document.getElementById('auditWeakCount');
        dom.auditReusedCount = document.getElementById('auditReusedCount');
        dom.auditOldCount = document.getElementById('auditOldCount');
        dom.auditIssuesList = document.getElementById('auditIssuesList');
        dom.btnRunAuditScan = document.getElementById('btnRunAuditScan');

        // AES Visualizer Tab
        dom.labPlaintextInput = document.getElementById('labPlaintextInput');
        dom.labKeyInput = document.getElementById('labKeyInput');
        dom.btnRunAesSimulation = document.getElementById('btnRunAesSimulation');
        dom.btnPrevRound = document.getElementById('btnPrevRound');
        dom.btnNextRound = document.getElementById('btnNextRound');
        dom.currentRoundTitle = document.getElementById('currentRoundTitle');
        dom.currentRoundDesc = document.getElementById('currentRoundDesc');
        dom.matrixStateInput = document.getElementById('matrixStateInput');
        dom.matrixStateSubBytes = document.getElementById('matrixStateSubBytes');
        dom.matrixStateShiftRows = document.getElementById('matrixStateShiftRows');
        dom.matrixStateMixColumns = document.getElementById('matrixStateMixColumns');
        dom.matrixStateAddRoundKey = document.getElementById('matrixStateAddRoundKey');
        dom.matrixRoundKey = document.getElementById('matrixRoundKey');

        // Threat Simulator Tab
        dom.tamperPlaintextInput = document.getElementById('tamperPlaintextInput');
        dom.tamperByteIndex = document.getElementById('tamperByteIndex');
        dom.btnRunTamperAttack = document.getElementById('btnRunTamperAttack');
        dom.tamperAttackResultBox = document.getElementById('tamperAttackResultBox');
        dom.nonceMsg1 = document.getElementById('nonceMsg1');
        dom.nonceMsg2 = document.getElementById('nonceMsg2');
        dom.btnRunNonceAttack = document.getElementById('btnRunNonceAttack');
        dom.nonceAttackResultBox = document.getElementById('nonceAttackResultBox');
        dom.btnRunKdfBenchmark = document.getElementById('btnRunKdfBenchmark');
        dom.kdfBenchmarkOutput = document.getElementById('kdfBenchmarkOutput');

        // Theory Accordion
        dom.theoryAccordion = document.getElementById('theoryAccordion');

        // Toast
        dom.clipboardToast = document.getElementById('clipboardToast');
        dom.clipboardCountdownSec = document.getElementById('clipboardCountdownSec');
        dom.toastProgressBar = document.getElementById('toastProgressBar');
    }

    /* ==========================================================================
     * 2. AMBIENT CYBER CANVAS BACKGROUND
     * ========================================================================== */
    function initMatrixCanvas() {
        const canvas = document.getElementById('matrixCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        function resize() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }
        resize();
        window.addEventListener('resize', resize);

        const hexChars = '0123456789ABCDEF';
        const fontSize = 16;
        let columns = Math.floor(canvas.width / fontSize);
        const drops = Array(columns).fill(1);

        function draw() {
            ctx.fillStyle = 'rgba(7, 9, 14, 0.08)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.fillStyle = '#06b6d4';
            ctx.font = `${fontSize}px JetBrains Mono`;

            for (let i = 0; i < drops.length; i++) {
                const text = hexChars.charAt(Math.floor(Math.random() * hexChars.length));
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }

        setInterval(draw, 50);
    }

    /* ==========================================================================
     * 3. NAVIGATION & AUTO-LOCK MANAGEMENT
     * ========================================================================== */
    function setupNavigation() {
        dom.navTabs.forEach(btn => {
            btn.addEventListener('click', () => {
                const targetTabId = btn.getAttribute('data-tab');
                switchTab(targetTabId);
            });
        });

        dom.btnLockVault.addEventListener('click', () => {
            lockVault();
        });

        // User activity resets the auto-lock timer
        ['mousemove', 'keydown', 'click', 'scroll'].forEach(evt => {
            window.addEventListener(evt, resetAutoLockTimer, { passive: true });
        });

        startAutoLockCountdown();
    }

    function switchTab(tabId) {
        state.activeTab = tabId;
        dom.navTabs.forEach(b => b.classList.toggle('active', b.getAttribute('data-tab') === tabId));
        dom.tabPanels.forEach(p => p.classList.toggle('active', p.id === tabId));

        if (tabId === 'tab-audit') {
            runSecurityAudit();
        } else if (tabId === 'tab-visualizer' && !state.aesTraceData) {
            runAesSimulation();
        }
    }

    function resetAutoLockTimer() {
        if (!state.unlocked) return;
        state.autoLockSecondsRemaining = 300; // 5 mins
        updateAutoLockBadge();
    }

    function startAutoLockCountdown() {
        if (state.autoLockInterval) clearInterval(state.autoLockInterval);
        state.autoLockInterval = setInterval(() => {
            if (!state.unlocked) return;
            state.autoLockSecondsRemaining--;
            updateAutoLockBadge();

            if (state.autoLockSecondsRemaining <= 0) {
                lockVault('Auto-locked due to 5 minutes of inactivity.');
            }
        }, 1000);
    }

    function updateAutoLockBadge() {
        const mins = Math.floor(state.autoLockSecondsRemaining / 60);
        const secs = state.autoLockSecondsRemaining % 60;
        dom.autoLockTimer.textContent = `Auto-Lock: ${mins}:${secs.toString().padStart(2, '0')}`;
    }

    /* ==========================================================================
     * 4. MASTER PASSWORD & VAULT UNLOCKING
     * ========================================================================== */
    function setupMasterLock() {
        // Toggle password visibility
        dom.btnToggleMasterVis.addEventListener('click', () => {
            const isPassword = dom.masterPasswordInput.type === 'password';
            dom.masterPasswordInput.type = isPassword ? 'text' : 'password';
            dom.btnToggleMasterVis.innerHTML = isPassword ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
        });

        // Master password entropy evaluator
        dom.masterPasswordInput.addEventListener('input', () => {
            const val = dom.masterPasswordInput.value;
            const evalResult = window.AegisCrypto.calculateEntropy(val);

            const percent = Math.min(100, Math.round((evalResult.bits / 100) * 100));
            dom.masterStrengthFill.style.width = `${percent}%`;
            dom.masterStrengthFill.style.backgroundColor = evalResult.color;
            dom.masterStrengthLabel.textContent = `Entropy: ${evalResult.bits} bits (${evalResult.rating})`;
            dom.masterStrengthLabel.style.color = evalResult.color;
        });

        // Enter key unlocks
        dom.masterPasswordInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                handleUnlock();
            }
        });

        dom.btnUnlockVault.addEventListener('click', handleUnlock);

        dom.btnLoadDemoDataset.addEventListener('click', async () => {
            dom.masterPasswordInput.value = 'DemoMasterPass#2026!';
            dom.masterPasswordInput.dispatchEvent(new Event('input'));
            await initializeDemoVault('DemoMasterPass#2026!');
        });
    }

    async function handleUnlock() {
        const password = dom.masterPasswordInput.value.trim();
        if (!password) {
            alert('Please enter a master password to derive cryptographic keys.');
            return;
        }

        dom.btnUnlockVault.disabled = true;
        dom.btnUnlockVault.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Deriving Keys via PBKDF2 (600,000 Rounds)...';

        try {
            const savedEnvelopeJson = localStorage.getItem(STORAGE_KEY);

            if (savedEnvelopeJson) {
                // Unlock existing stored vault
                const envelope = JSON.parse(savedEnvelopeJson);
                const decryptedItems = await window.AegisCrypto.unlockVault(password, envelope);
                state.vaultEnvelope = envelope;
                state.items = decryptedItems;
            } else {
                // Initialize brand new vault
                const envelope = await window.AegisCrypto.initializeVault(password, DEMO_ITEMS);
                state.vaultEnvelope = envelope;
                state.items = [...DEMO_ITEMS];
                localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
            }

            state.unlocked = true;
            state.masterPassword = password;
            dom.lockScreenOverlay.style.display = 'none';
            dom.statusDot.classList.remove('locked');
            dom.statusText.textContent = 'Vault Active (AES-256-GCM)';

            resetAutoLockTimer();
            renderVaultItems();
            updateVaultStats();
            runSecurityAudit();
        } catch (error) {
            alert(`Authentication Error: ${error.message}`);
        } finally {
            dom.btnUnlockVault.disabled = false;
            dom.btnUnlockVault.innerHTML = '<i class="fa-solid fa-lock-open"></i> Unlock Encrypted Vault';
        }
    }

    async function initializeDemoVault(password) {
        dom.btnLoadDemoDataset.disabled = true;
        dom.btnLoadDemoDataset.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Initializing Encrypted Dataset...';

        try {
            const envelope = await window.AegisCrypto.initializeVault(password, DEMO_ITEMS);
            state.vaultEnvelope = envelope;
            state.items = [...DEMO_ITEMS];
            localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));

            state.unlocked = true;
            state.masterPassword = password;
            dom.lockScreenOverlay.style.display = 'none';
            dom.statusDot.classList.remove('locked');
            dom.statusText.textContent = 'Vault Active (Demo Dataset)';

            resetAutoLockTimer();
            renderVaultItems();
            updateVaultStats();
            runSecurityAudit();
        } catch (err) {
            alert(`Failed to initialize demo vault: ${err.message}`);
        } finally {
            dom.btnLoadDemoDataset.disabled = false;
            dom.btnLoadDemoDataset.innerHTML = '<i class="fa-solid fa-flask"></i> Load Demo CNS Academic Dataset';
        }
    }

    function lockVault(reason = '') {
        state.unlocked = false;
        state.items = [];
        state.vaultEnvelope = null;
        window.AegisCrypto.lockVault(); // Purge activeKey from memory

        dom.lockScreenOverlay.style.display = 'flex';
        dom.masterPasswordInput.value = '';
        dom.masterStrengthFill.style.width = '0%';
        dom.masterStrengthLabel.textContent = reason || 'Vault locked. Enter master password to unlock.';
        dom.masterStrengthLabel.style.color = '#ef4444';
        dom.statusDot.classList.add('locked');
        dom.statusText.textContent = 'Vault Locked (Key Purged)';
        renderVaultItems();
    }

    /* ==========================================================================
     * 5. VAULT RENDERING, SEARCH & CRUD
     * ========================================================================== */
    function setupVaultHandlers() {
        // Search Input
        dom.vaultSearchInput.addEventListener('input', (e) => {
            state.searchQuery = e.target.value.toLowerCase().trim();
            renderVaultItems();
        });

        // Category Filter Buttons
        dom.categoryFilterContainer.addEventListener('click', (e) => {
            if (e.target.classList.contains('filter-pill-btn')) {
                dom.categoryFilterContainer.querySelectorAll('.filter-pill-btn').forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                state.filteredCategory = e.target.getAttribute('data-category');
                renderVaultItems();
            }
        });

        // Add New Item Button
        dom.btnAddNewItem.addEventListener('click', () => {
            openItemModal();
        });

        // Export Vault
        dom.btnExportVault.addEventListener('click', exportVaultBackup);

        // Import Vault
        dom.btnImportVault.addEventListener('click', () => dom.fileVaultImport.click());
        dom.fileVaultImport.addEventListener('change', handleImportVaultFile);

        // Modal Controls
        dom.btnCloseItemModal.addEventListener('click', closeItemModal);
        dom.btnCancelItemModal.addEventListener('click', closeItemModal);
        dom.vaultItemForm.addEventListener('submit', handleSaveItem);

        // Modal Password Generator Button
        dom.btnGenPasswordForModal.addEventListener('click', () => {
            const pwd = window.AegisCrypto.generatePassword({ length: 22 });
            dom.itemPasswordField.value = pwd;
            updateModalPasswordEntropy();
        });

        dom.itemPasswordField.addEventListener('input', updateModalPasswordEntropy);
    }

    function updateModalPasswordEntropy() {
        const val = dom.itemPasswordField.value;
        const evalRes = window.AegisCrypto.calculateEntropy(val);
        const percent = Math.min(100, Math.round((evalRes.bits / 100) * 100));
        dom.modalPasswordEntropyFill.style.width = `${percent}%`;
        dom.modalPasswordEntropyFill.style.backgroundColor = evalRes.color;
        dom.modalPasswordEntropyLabel.textContent = `${evalRes.bits} bits entropy (${evalRes.rating})`;
        dom.modalPasswordEntropyLabel.style.color = evalRes.color;
    }

    function renderVaultItems() {
        if (!state.unlocked) {
            dom.vaultItemsGrid.innerHTML = `
                <div class="vault-empty-state">
                    <div class="empty-icon"><i class="fa-solid fa-lock"></i></div>
                    <h3>Vault is Currently Locked</h3>
                    <p>Enter your master password to decrypt vault contents.</p>
                </div>
            `;
            return;
        }

        const filtered = state.items.filter(item => {
            const matchesCategory = state.filteredCategory === 'all' || item.category === state.filteredCategory;
            const matchesSearch = !state.searchQuery ||
                item.title.toLowerCase().includes(state.searchQuery) ||
                (item.username && item.username.toLowerCase().includes(state.searchQuery)) ||
                (item.notes && item.notes.toLowerCase().includes(state.searchQuery));
            return matchesCategory && matchesSearch;
        });

        if (filtered.length === 0) {
            dom.vaultItemsGrid.innerHTML = `
                <div class="vault-empty-state">
                    <div class="empty-icon"><i class="fa-solid fa-box-open"></i></div>
                    <h3>No Credentials Found</h3>
                    <p>No vault items match your current filter or search criteria.</p>
                </div>
            `;
            return;
        }

        dom.vaultItemsGrid.innerHTML = filtered.map(item => {
            const entropy = window.AegisCrypto.calculateEntropy(item.password);
            const categoryIcon = getCategoryIcon(item.category);

            return `
                <div class="vault-item-card" data-id="${item.id}">
                    <div class="item-card-header">
                        <div class="item-category-icon-box">
                            <i class="${categoryIcon}"></i>
                        </div>
                        <div class="item-title-group">
                            <h4 class="item-title">${escapeHtml(item.title)}</h4>
                            ${item.url ? `<a href="${escapeHtml(item.url)}" target="_blank" rel="noopener" class="item-url-or-tag">${escapeHtml(item.url.replace(/^https?:\/\//, ''))}</a>` : `<span class="item-url-or-tag">${item.category.toUpperCase()}</span>`}
                        </div>
                        <button class="item-star-btn ${item.favorite ? 'starred' : ''}" data-action="toggle-favorite" data-id="${item.id}" title="Favorite">
                            <i class="${item.favorite ? 'fa-solid' : 'fa-regular'} fa-star"></i>
                        </button>
                    </div>

                    ${item.username ? `
                    <div class="item-data-row">
                        <span class="item-data-label">Identity</span>
                        <span class="item-data-val">${escapeHtml(item.username)}</span>
                        <button class="item-copy-btn" data-action="copy-val" data-val="${escapeHtml(item.username)}" title="Copy Identity">
                            <i class="fa-regular fa-copy"></i>
                        </button>
                    </div>` : ''}

                    <div class="item-data-row">
                        <span class="item-data-label">Password</span>
                        <span class="item-data-val item-password-masked" id="pwd-display-${item.id}">••••••••••••••••</span>
                        <div style="display: flex; gap: 4px;">
                            <button class="item-toggle-vis-btn" data-action="toggle-pwd-vis" data-id="${item.id}" title="Toggle Visibility">
                                <i class="fa-regular fa-eye"></i>
                            </button>
                            <button class="item-copy-btn" data-action="copy-pwd" data-id="${item.id}" title="Copy Password">
                                <i class="fa-solid fa-copy"></i>
                            </button>
                        </div>
                    </div>

                    ${item.notes ? `
                    <div style="font-size: 0.8rem; color: var(--text-muted); line-height: 1.4; max-height: 38px; overflow: hidden; text-overflow: ellipsis;">
                        ${escapeHtml(item.notes)}
                    </div>` : ''}

                    <div class="item-footer">
                        <span class="entropy-chip" style="background: ${entropy.color}22; color: ${entropy.color}; border: 1px solid ${entropy.color}44;">
                            <i class="fa-solid fa-bolt"></i> ${entropy.bits} bits (${entropy.rating})
                        </span>
                        <div class="item-card-actions">
                            <button class="card-action-icon-btn" data-action="edit-item" data-id="${item.id}" title="Edit Item">
                                <i class="fa-solid fa-pen-to-square"></i>
                            </button>
                            <button class="card-action-icon-btn delete-btn" data-action="delete-item" data-id="${item.id}" title="Delete Item">
                                <i class="fa-solid fa-trash-can"></i>
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        attachVaultCardListeners();
    }

    function attachVaultCardListeners() {
        dom.vaultItemsGrid.querySelectorAll('button[data-action]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                const action = btn.getAttribute('data-action');
                const id = btn.getAttribute('data-id');
                const item = state.items.find(i => i.id === id);

                if (action === 'toggle-favorite' && item) {
                    item.favorite = !item.favorite;
                    saveItemsToVault();
                    renderVaultItems();
                } else if (action === 'toggle-pwd-vis' && item) {
                    const span = document.getElementById(`pwd-display-${id}`);
                    const isMasked = span.classList.contains('item-password-masked');
                    if (isMasked) {
                        span.textContent = item.password;
                        span.classList.remove('item-password-masked');
                        btn.innerHTML = '<i class="fa-regular fa-eye-slash"></i>';
                        // Auto-hide after 10 seconds
                        setTimeout(() => {
                            if (span) {
                                span.textContent = '••••••••••••••••';
                                span.classList.add('item-password-masked');
                                btn.innerHTML = '<i class="fa-regular fa-eye"></i>';
                            }
                        }, 10000);
                    } else {
                        span.textContent = '••••••••••••••••';
                        span.classList.add('item-password-masked');
                        btn.innerHTML = '<i class="fa-regular fa-eye"></i>';
                    }
                } else if (action === 'copy-pwd' && item) {
                    copyToClipboardWithAutoClear(item.password, 'Password');
                } else if (action === 'copy-val') {
                    const val = btn.getAttribute('data-val');
                    copyToClipboardWithAutoClear(val, 'Identity');
                } else if (action === 'edit-item' && item) {
                    openItemModal(item);
                } else if (action === 'delete-item' && item) {
                    if (confirm(`Are you sure you want to delete "${item.title}"?`)) {
                        state.items = state.items.filter(i => i.id !== id);
                        saveItemsToVault();
                        renderVaultItems();
                        updateVaultStats();
                        runSecurityAudit();
                    }
                }
            });
        });
    }

    function getCategoryIcon(cat) {
        switch (cat) {
            case 'card': return 'fa-solid fa-credit-card';
            case 'note': return 'fa-solid fa-note-sticky';
            case 'api': return 'fa-solid fa-terminal';
            default: return 'fa-solid fa-globe';
        }
    }

    async function saveItemsToVault() {
        if (!state.unlocked) return;
        const updatedEnvelope = await window.AegisCrypto.saveVault(state.items);
        state.vaultEnvelope = updatedEnvelope;
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updatedEnvelope));
    }

    function updateVaultStats() {
        dom.statTotalItems.textContent = state.items.length;
        if (state.items.length === 0) {
            dom.statHealthScore.textContent = '100%';
            return;
        }

        let totalScore = 0;
        state.items.forEach(item => {
            const entropy = window.AegisCrypto.calculateEntropy(item.password);
            totalScore += Math.min(100, entropy.bits);
        });

        const avgScore = Math.round(totalScore / state.items.length);
        dom.statHealthScore.textContent = `${avgScore}%`;
    }

    /* ==========================================================================
     * 6. MODAL CRUD
     * ========================================================================== */
    function openItemModal(itemToEdit = null) {
        if (itemToEdit) {
            dom.itemModalTitle.innerHTML = '<i class="fa-solid fa-pen-to-square text-cyan"></i> Edit Vault Entry';
            dom.itemIdField.value = itemToEdit.id;
            dom.itemCategoryField.value = itemToEdit.category;
            dom.itemTitleField.value = itemToEdit.title;
            dom.itemUsernameField.value = itemToEdit.username || '';
            dom.itemPasswordField.value = itemToEdit.password;
            dom.itemUrlField.value = itemToEdit.url || '';
            dom.itemNotesField.value = itemToEdit.notes || '';
        } else {
            dom.itemModalTitle.innerHTML = '<i class="fa-solid fa-plus text-cyan"></i> New Vault Entry';
            dom.vaultItemForm.reset();
            dom.itemIdField.value = '';
            // Auto generate initial strong password
            dom.itemPasswordField.value = window.AegisCrypto.generatePassword({ length: 20 });
        }

        updateModalPasswordEntropy();
        dom.itemModalOverlay.classList.add('active');
    }

    function closeItemModal() {
        dom.itemModalOverlay.classList.remove('active');
    }

    async function handleSaveItem(e) {
        e.preventDefault();

        const id = dom.itemIdField.value;
        const category = dom.itemCategoryField.value;
        const title = dom.itemTitleField.value.trim();
        const username = dom.itemUsernameField.value.trim();
        const password = dom.itemPasswordField.value.trim();
        const url = dom.itemUrlField.value.trim();
        const notes = dom.itemNotesField.value.trim();

        if (!title || !password) {
            alert('Title and Password are required fields.');
            return;
        }

        if (id) {
            // Update existing
            const item = state.items.find(i => i.id === id);
            if (item) {
                if (item.password !== password) {
                    if (!item.history) item.history = [];
                    item.history.push({ password: item.password, changedAt: new Date().toISOString() });
                }
                item.category = category;
                item.title = title;
                item.username = username;
                item.password = password;
                item.url = url;
                item.notes = notes;
                item.updatedAt = new Date().toISOString();
            }
        } else {
            // Create new
            const newItem = {
                id: 'item-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7),
                category,
                title,
                username,
                password,
                url,
                notes,
                favorite: false,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                history: []
            };
            state.items.unshift(newItem);
        }

        await saveItemsToVault();
        renderVaultItems();
        updateVaultStats();
        runSecurityAudit();
        closeItemModal();
    }

    /* ==========================================================================
     * 7. CLIPBOARD PURGE COUNTDOWN TOAST
     * ========================================================================== */
    function copyToClipboardWithAutoClear(text, label = 'Secret') {
        navigator.clipboard.writeText(text).then(() => {
            showClipboardCountdownToast(text, label);
        }).catch(err => {
            console.error('Clipboard copy failed:', err);
            alert('Failed to copy to clipboard.');
        });
    }

    function showClipboardCountdownToast(secretText, label) {
        if (state.clipboardTimeout) {
            clearTimeout(state.clipboardTimeout);
        }

        dom.clipboardToast.classList.add('active');
        let secondsLeft = 30;
        dom.clipboardCountdownSec.textContent = `${secondsLeft}s`;
        dom.toastProgressBar.style.width = '100%';

        const interval = setInterval(() => {
            secondsLeft--;
            dom.clipboardCountdownSec.textContent = `${secondsLeft}s`;
            dom.toastProgressBar.style.width = `${(secondsLeft / 30) * 100}%`;

            if (secondsLeft <= 0) {
                clearInterval(interval);
                // Purge clipboard if it still contains the secret
                navigator.clipboard.readText().then(currentClip => {
                    if (currentClip === secretText) {
                        navigator.clipboard.writeText('');
                    }
                }).catch(() => {});
                dom.clipboardToast.classList.remove('active');
            }
        }, 1000);

        state.clipboardTimeout = interval;
    }

    /* ==========================================================================
     * 8. EXPORT & IMPORT ENCRYPTED VAULT (.AEGIS)
     * ========================================================================== */
    function exportVaultBackup() {
        if (!state.vaultEnvelope) {
            alert('Vault is not loaded.');
            return;
        }

        const backupData = JSON.stringify(state.vaultEnvelope, null, 2);
        const blob = new Blob([backupData], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `AegisVault_Backup_${new Date().toISOString().slice(0, 10)}.aegis`;
        a.click();
        URL.revokeObjectURL(url);
    }

    function handleImportVaultFile(e) {
        const file = e.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = async (event) => {
            try {
                const parsed = JSON.parse(event.target.result);
                if (!parsed.cryptoPayload || !parsed.kdf || !parsed.authVerifierHex) {
                    throw new Error('Invalid AegisVault encrypted format.');
                }

                const password = prompt('Enter master password to unlock and import this backup vault:');
                if (!password) return;

                const decryptedItems = await window.AegisCrypto.unlockVault(password, parsed);
                state.vaultEnvelope = parsed;
                state.items = decryptedItems;
                state.unlocked = true;
                state.masterPassword = password;
                localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));

                dom.lockScreenOverlay.style.display = 'none';
                renderVaultItems();
                updateVaultStats();
                runSecurityAudit();
                alert(`Successfully imported ${decryptedItems.length} encrypted credentials!`);
            } catch (err) {
                alert(`Import failed: ${err.message}`);
            }
        };
        reader.readAsText(file);
    }

    /* ==========================================================================
     * 9. PASSWORD GENERATOR & ENTROPY LAB
     * ========================================================================== */
    function setupGenerator() {
        let isDiceware = false;

        dom.modeRandomChars.addEventListener('click', () => {
            isDiceware = false;
            dom.modeRandomChars.classList.add('active');
            dom.modeDiceware.classList.remove('active');
            dom.lengthControlRow.style.display = 'flex';
            dom.wordsControlRow.style.display = 'none';
            document.getElementById('charTogglesRow').style.display = 'flex';
            document.getElementById('charTogglesRow2').style.display = 'flex';
            updateGeneratedPassword();
        });

        dom.modeDiceware.addEventListener('click', () => {
            isDiceware = true;
            dom.modeDiceware.classList.add('active');
            dom.modeRandomChars.classList.remove('active');
            dom.lengthControlRow.style.display = 'none';
            dom.wordsControlRow.style.display = 'flex';
            document.getElementById('charTogglesRow').style.display = 'none';
            document.getElementById('charTogglesRow2').style.display = 'none';
            updateGeneratedPassword();
        });

        dom.genLengthSlider.addEventListener('input', (e) => {
            dom.genLengthVal.textContent = e.target.value;
            updateGeneratedPassword();
        });

        dom.genWordsSlider.addEventListener('input', (e) => {
            dom.genWordsVal.textContent = e.target.value;
            updateGeneratedPassword();
        });

        [dom.chkUpper, dom.chkLower, dom.chkDigits, dom.chkSymbols, dom.chkAvoidAmbiguous].forEach(chk => {
            chk.addEventListener('change', updateGeneratedPassword);
        });

        dom.btnRegeneratePassword.addEventListener('click', updateGeneratedPassword);

        dom.btnCopyGeneratedPassword.addEventListener('click', () => {
            const pwd = dom.generatedPasswordDisplay.textContent.trim();
            copyToClipboardWithAutoClear(pwd, 'Generated Token');
        });

        function updateGeneratedPassword() {
            let pwd = '';
            if (isDiceware) {
                const words = parseInt(dom.genWordsSlider.value);
                pwd = window.AegisCrypto.generatePassphrase(words, '-', true);
            } else {
                pwd = window.AegisCrypto.generatePassword({
                    length: parseInt(dom.genLengthSlider.value),
                    useUpper: dom.chkUpper.checked,
                    useLower: dom.chkLower.checked,
                    useDigits: dom.chkDigits.checked,
                    useSymbols: dom.chkSymbols.checked,
                    avoidAmbiguous: dom.chkAvoidAmbiguous.checked
                });
            }

            dom.generatedPasswordDisplay.textContent = pwd;

            // Entropy Evaluation
            const evalResult = window.AegisCrypto.calculateEntropy(pwd);
            dom.genEntropyBadge.innerHTML = `<i class="fa-solid fa-bolt"></i> ${evalResult.bits} bits (${evalResult.rating})`;
            dom.genEntropyBadge.style.background = `${evalResult.color}22`;
            dom.genEntropyBadge.style.color = evalResult.color;

            dom.entropyNumberDisplay.textContent = `${evalResult.bits} bits`;
            dom.entropyNumberDisplay.style.color = evalResult.color;
            dom.entropyRatingDisplay.textContent = evalResult.rating;
            dom.entropyRatingDisplay.style.color = evalResult.color;

            const percent = Math.min(100, Math.round((evalResult.bits / 100) * 100));
            dom.entropyMeterFill.style.width = `${percent}%`;
            dom.entropyMeterFill.style.backgroundColor = evalResult.color;

            dom.crackTimeOnline.textContent = evalResult.crackTimes.online;
            dom.crackTimeFastGpu.textContent = evalResult.crackTimes.fastGpu;
            dom.crackTimeCluster.textContent = evalResult.crackTimes.cluster;
            dom.crackTimeQuantum.textContent = evalResult.crackTimes.supercomputer;
        }

        updateGeneratedPassword();
    }

    /* ==========================================================================
     * 10. SECURITY AUDIT & HEALTH SCANNER
     * ========================================================================== */
    async function runSecurityAudit() {
        if (!state.unlocked || state.items.length === 0) {
            dom.auditScoreVal.textContent = '100%';
            dom.auditWeakCount.textContent = '0';
            dom.auditReusedCount.textContent = '0';
            dom.auditOldCount.textContent = '0';
            dom.auditIssuesList.innerHTML = `<p style="color: var(--text-muted); padding: 12px 0;">No credentials in vault to analyze.</p>`;
            return;
        }

        const issues = [];
        let weakCount = 0;
        let oldCount = 0;
        const passwordMap = {};

        const now = Date.now();
        const ninetyDaysMs = 90 * 86400000;

        for (const item of state.items) {
            // 1. Weak password check (< 50 bits)
            const entropy = window.AegisCrypto.calculateEntropy(item.password);
            if (entropy.bits < 50) {
                weakCount++;
                issues.push({
                    type: 'weak',
                    severity: 'critical',
                    item,
                    title: `Low Entropy (${entropy.bits} bits): "${item.title}"`,
                    desc: `Estimated offline GPU crack time is only ${entropy.crackTimes.fastGpu}. Upgrade to at least 16 random characters.`,
                    fixAction: 'generate'
                });
            }

            // 2. Reused password check
            if (!passwordMap[item.password]) {
                passwordMap[item.password] = [];
            }
            passwordMap[item.password].push(item);

            // 3. Stale password check (> 90 days)
            const created = new Date(item.createdAt).getTime();
            if (now - created > ninetyDaysMs) {
                oldCount++;
                issues.push({
                    type: 'stale',
                    severity: 'warning',
                    item,
                    title: `Stale Credential (> 90 Days): "${item.title}"`,
                    desc: `Password has remained unchanged for ${Math.round((now - created) / 86400000)} days. Rotating keys limits blast radius from historical data leaks.`,
                    fixAction: 'generate'
                });
            }

            // 4. Breach check (k-Anonymity simulation)
            const breach = await window.AegisCrypto.checkBreachStatus(item.password);
            if (breach.isCompromised) {
                issues.push({
                    type: 'breached',
                    severity: 'critical',
                    item,
                    title: `Compromised Password Found in Breach: "${item.title}"`,
                    desc: `Matches known database leak (SHA-1 prefix: ${breach.prefix}). ${breach.privacyNote}`,
                    fixAction: 'generate'
                });
            }
        }

        // Duplicate / reused count
        let reusedCount = 0;
        Object.entries(passwordMap).forEach(([pwd, itemList]) => {
            if (itemList.length > 1) {
                reusedCount += itemList.length;
                issues.push({
                    type: 'reused',
                    severity: 'high',
                    item: itemList[0],
                    title: `Password Reused across ${itemList.length} Services`,
                    desc: `Shared between: ${itemList.map(i => `"${i.title}"`).join(', ')}. Credential stuffing attacks compromise all accounts if one service leaks.`,
                    fixAction: 'generate'
                });
            }
        });

        // Compute overall health score
        let score = 100;
        score -= weakCount * 18;
        score -= reusedCount * 12;
        score -= oldCount * 5;
        score = Math.max(10, Math.min(100, score));

        dom.auditScoreVal.textContent = `${score}%`;
        dom.auditScoreVal.style.color = score > 80 ? 'var(--neon-emerald)' : score > 50 ? 'var(--neon-amber)' : 'var(--neon-coral)';

        dom.auditWeakCount.textContent = weakCount;
        dom.auditReusedCount.textContent = reusedCount;
        dom.auditOldCount.textContent = oldCount;

        if (issues.length === 0) {
            dom.auditIssuesList.innerHTML = `
                <div class="attack-result-banner success">
                    <i class="fa-solid fa-circle-check" style="font-size: 1.2rem;"></i>
                    <div>
                        <strong>All Cryptographic Health Checks Passed!</strong>
                        <p style="margin-top: 4px; color: var(--text-secondary);">No weak entropy, credential reuse, stale records, or breached hashes detected.</p>
                    </div>
                </div>
            `;
            return;
        }

        dom.auditIssuesList.innerHTML = issues.map(iss => `
            <div class="audit-issue-row">
                <div style="display: flex; align-items: center; gap: 14px;">
                    <i class="fa-solid ${iss.severity === 'critical' ? 'fa-triangle-exclamation text-coral' : 'fa-circle-exclamation text-amber'}" style="font-size: 1.3rem;"></i>
                    <div>
                        <h4 style="font-size: 0.95rem; color: #fff; margin-bottom: 2px;">${escapeHtml(iss.title)}</h4>
                        <p style="font-size: 0.82rem; color: var(--text-secondary); max-width: 700px;">${escapeHtml(iss.desc)}</p>
                    </div>
                </div>
                <button class="btn-primary" data-action="fix-issue" data-id="${iss.item.id}" style="padding: 6px 14px; font-size: 0.8rem; white-space: nowrap;">
                    <i class="fa-solid fa-wand-magic-sparkles"></i> Fix: Rotate Key
                </button>
            </div>
        `).join('');

        dom.auditIssuesList.querySelectorAll('button[data-action="fix-issue"]').forEach(b => {
            b.addEventListener('click', () => {
                const id = b.getAttribute('data-id');
                const itm = state.items.find(i => i.id === id);
                if (itm) {
                    openItemModal(itm);
                    dom.btnGenPasswordForModal.click();
                }
            });
        });
    }

    /* ==========================================================================
     * 11. INTERACTIVE AES-256 VISUALIZER
     * ========================================================================== */
    function setupAesVisualizer() {
        dom.btnRunAesSimulation.addEventListener('click', runAesSimulation);

        dom.btnPrevRound.addEventListener('click', () => {
            if (state.currentAesRound > 0) {
                state.currentAesRound--;
                renderAesRound(state.currentAesRound);
            }
        });

        dom.btnNextRound.addEventListener('click', () => {
            if (state.currentAesRound < 14) {
                state.currentAesRound++;
                renderAesRound(state.currentAesRound);
            }
        });
    }

    function runAesSimulation() {
        const textStr = dom.labPlaintextInput.value || 'AegisSec2026Lab!';
        const keyStr = dom.labKeyInput.value || 'MasterAES256SecurityProjectKey!';

        // Pad or truncate to 16 bytes plaintext
        const textBytes = new Uint8Array(16);
        const encodedText = new TextEncoder().encode(textStr);
        textBytes.set(encodedText.slice(0, 16));

        // Pad or truncate to 32 bytes key
        const keyBytes = new Uint8Array(32);
        const encodedKey = new TextEncoder().encode(keyStr);
        keyBytes.set(encodedKey.slice(0, 32));

        const result = window.AegisVisualizer.simulateAES256(textBytes, keyBytes);
        state.aesTraceData = result.trace;
        state.currentAesRound = 1;
        renderAesRound(1);
    }

    function renderAesRound(roundIndex) {
        if (!state.aesTraceData || !state.aesTraceData[roundIndex]) return;

        const roundData = state.aesTraceData[roundIndex];
        dom.currentRoundTitle.textContent = roundData.title;
        dom.currentRoundDesc.textContent = roundData.description;

        dom.btnPrevRound.disabled = roundIndex === 0;
        dom.btnNextRound.disabled = roundIndex === 14;

        if (roundIndex === 0) {
            renderMatrix(dom.matrixStateInput, roundData.steps.initial);
            renderMatrix(dom.matrixStateSubBytes, roundData.steps.initial, true); // N/A
            renderMatrix(dom.matrixStateShiftRows, roundData.steps.initial, true);
            renderMatrix(dom.matrixStateMixColumns, roundData.steps.initial, true);
            renderMatrix(dom.matrixStateAddRoundKey, roundData.steps.addRoundKey);
        } else {
            renderMatrix(dom.matrixStateInput, roundData.steps.start);
            renderMatrix(dom.matrixStateSubBytes, roundData.steps.subBytes);
            renderMatrix(dom.matrixStateShiftRows, roundData.steps.shiftRows);
            if (roundData.steps.mixColumns) {
                renderMatrix(dom.matrixStateMixColumns, roundData.steps.mixColumns);
            } else {
                renderMatrix(dom.matrixStateMixColumns, roundData.steps.shiftRows, true); // Omitted in final round
            }
            renderMatrix(dom.matrixStateAddRoundKey, roundData.steps.addRoundKey);
        }

        renderMatrix(dom.matrixRoundKey, window.AegisVisualizer.bytesToState(roundData.roundKey));
    }

    function renderMatrix(container, stateMatrix, isOmitted = false) {
        container.innerHTML = '';
        for (let r = 0; r < 4; r++) {
            for (let c = 0; c < 4; c++) {
                const val = stateMatrix[r][c];
                const cell = document.createElement('div');
                cell.className = 'matrix-cell';
                if (isOmitted) {
                    cell.textContent = '--';
                    cell.style.color = 'var(--text-muted)';
                    cell.style.opacity = '0.4';
                } else {
                    cell.textContent = val.toString(16).padStart(2, '0').toUpperCase();
                    cell.title = `Row ${r}, Col ${c} (Dec: ${val})`;
                }
                container.appendChild(cell);
            }
        }
    }

    /* ==========================================================================
     * 12. THREAT & ATTACK SIMULATOR
     * ========================================================================== */
    function setupAttackSimulator() {
        // Attack 1: Bit-Flipping
        dom.btnRunTamperAttack.addEventListener('click', async () => {
            const text = dom.tamperPlaintextInput.value || 'TRANSFER $10,000';
            const byteIdx = parseInt(dom.tamperByteIndex.value) || 0;

            dom.btnRunTamperAttack.disabled = true;
            dom.btnRunTamperAttack.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Encrypting, Flipping Bit & Decrypting...';

            const res = await window.AegisAttackSimulator.simulateBitFlippingAttack(text, byteIdx);

            dom.tamperAttackResultBox.style.display = 'block';
            dom.tamperAttackResultBox.innerHTML = `
                <div class="attack-interactive-box">
                    <div style="margin-bottom: 6px;"><strong>Original Ciphertext (Hex):</strong></div>
                    <div style="word-break: break-all; color: var(--neon-cyan); margin-bottom: 10px;">${res.originalFullHex}</div>

                    <div style="margin-bottom: 6px;"><strong>Tampered Ciphertext (Bit flipped at byte [${res.targetByteIndex}]):</strong></div>
                    <div style="word-break: break-all; color: var(--neon-coral); margin-bottom: 10px;">
                        ${res.tamperedFullHex.substring(0, res.targetByteIndex * 2)}<span style="background: rgba(239, 68, 68, 0.4); font-weight: bold; padding: 2px 4px; border-radius: 4px;">${res.tamperedByteHex}</span>${res.tamperedFullHex.substring(res.targetByteIndex * 2 + 2)}
                    </div>

                    <div style="margin-bottom: 6px;"><strong>Expected 128-bit Auth Tag (GHASH):</strong></div>
                    <div style="word-break: break-all; color: var(--neon-amber);">${res.authTagHex}</div>
                </div>

                <div class="attack-result-banner ${res.decryptionStatus === 'BLOCKED_BY_AEAD' ? 'success' : 'danger'}">
                    <i class="fa-solid fa-shield-halved" style="font-size: 1.4rem;"></i>
                    <div>
                        <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 2px;">
                            ${res.decryptionStatus === 'BLOCKED_BY_AEAD' ? '✓ ATTACK NEUTRALIZED: AEAD TAG MISMATCH DETECTED' : '⚠ VULNERABLE'}
                        </h4>
                        <p style="margin-bottom: 6px;">${res.errorMessage}</p>
                        <p style="font-size: 0.8rem; color: var(--text-secondary);">${res.cnsExplanation}</p>
                    </div>
                </div>
            `;

            dom.btnRunTamperAttack.disabled = false;
            dom.btnRunTamperAttack.innerHTML = '<i class="fa-solid fa-bolt"></i> Intercept, Flip Bit & Attempt Decryption';
        });

        // Attack 2: Nonce Reuse
        dom.btnRunNonceAttack.addEventListener('click', async () => {
            const m1 = dom.nonceMsg1.value || 'CONFIDENTIAL_MSG_1';
            const m2 = dom.nonceMsg2.value || 'AUTHORIZATION_MSG_2';

            dom.btnRunNonceAttack.disabled = true;
            dom.btnRunNonceAttack.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Executing Keystream Analysis...';

            const res = await window.AegisAttackSimulator.simulateNonceReuseVulnerability(m1, m2);

            dom.nonceAttackResultBox.style.display = 'block';
            dom.nonceAttackResultBox.innerHTML = `
                <div class="attack-interactive-box">
                    <div style="margin-bottom: 4px;"><strong>Reused Nonce / IV (96-bit):</strong> <span style="color: var(--neon-amber);">${res.reusedIvHex}</span></div>
                    <div style="margin-bottom: 4px;"><strong>Ciphertext C1:</strong> <span style="color: var(--neon-cyan);">${res.c1Hex}</span></div>
                    <div style="margin-bottom: 4px;"><strong>Ciphertext C2:</strong> <span style="color: var(--neon-cyan);">${res.c2Hex}</span></div>
                    <div style="margin-top: 8px; margin-bottom: 4px;"><strong>C1 &oplus; C2 (Leaked Plaintext XOR Stream):</strong></div>
                    <div style="word-break: break-all; color: var(--neon-coral); font-weight: bold;">${res.c1XorC2Hex}</div>
                </div>

                <div class="attack-result-banner danger">
                    <i class="fa-solid fa-radiation" style="font-size: 1.4rem;"></i>
                    <div>
                        <h4 style="font-size: 0.95rem; font-weight: 700; margin-bottom: 2px;">
                            FATAL ZERO-DAY LEAK: KEYSTREAM COLLISION
                        </h4>
                        <p style="font-size: 0.82rem; color: #fca5a5;">${res.cnsExplanation}</p>
                    </div>
                </div>
            `;

            dom.btnRunNonceAttack.disabled = false;
            dom.btnRunNonceAttack.innerHTML = '<i class="fa-solid fa-radiation"></i> Execute Nonce Reuse Analysis';
        });

        // Attack 3: KDF Work-Factor Benchmark
        dom.btnRunKdfBenchmark.addEventListener('click', async () => {
            dom.btnRunKdfBenchmark.disabled = true;
            dom.btnRunKdfBenchmark.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Benchmarking PBKDF2 Rounds...';

            dom.kdfBenchmarkOutput.innerHTML = `
                <div style="text-align: center; padding: 24px;">
                    <i class="fa-solid fa-microchip fa-spin text-cyan" style="font-size: 2rem; margin-bottom: 12px;"></i>
                    <p>Executing WebCrypto PBKDF2 key derivation cycles on your CPU hardware...</p>
                </div>
            `;

            const results = await window.AegisAttackSimulator.benchmarkKdfWorkFactor();

            dom.kdfBenchmarkOutput.innerHTML = `
                <table class="crack-times-table" style="margin-top: 10px;">
                    <thead>
                        <tr>
                            <th>PBKDF2-HMAC-SHA256 Iterations</th>
                            <th>Browser Derivation Time</th>
                            <th>8x RTX 4090 GPU Cluster Hash Rate</th>
                            <th>Brute-Force Work Factor</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${results.map(r => `
                            <tr ${r.iterations === 600000 ? 'style="background: rgba(6, 182, 212, 0.08); font-weight: bold;"' : ''}>
                                <td><span style="font-family: var(--font-mono); color: var(--neon-cyan);">${r.iterations.toLocaleString()}</span></td>
                                <td><span style="font-family: var(--font-mono);">${r.clientTimeMs} ms</span></td>
                                <td><span style="font-family: var(--font-mono); color: var(--neon-amber);">${r.gpuAttemptsPerSec}</span></td>
                                <td><span style="font-family: var(--font-mono); color: var(--neon-emerald);">${r.relativeCost}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
                <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 12px;">
                    * Notice how 600,000 iterations forces a GPU cluster that can ordinarily test 3 Billion MD5/s down to only a few hundred attempts/sec, mathematically crushing dictionary attacks.
                </div>
            `;

            dom.btnRunKdfBenchmark.disabled = false;
            dom.btnRunKdfBenchmark.innerHTML = '<i class="fa-solid fa-microchip"></i> Run Live KDF Benchmark';
        });
    }

    /* ==========================================================================
     * 13. CNS THEORY & VIVA ACCORDION
     * ========================================================================== */
    function setupTheoryAccordion() {
        dom.theoryAccordion.querySelectorAll('.viva-question').forEach(header => {
            header.addEventListener('click', () => {
                const item = header.parentElement;
                item.classList.toggle('open');
            });
        });
    }

    /* ==========================================================================
     * UTILITY FUNCTIONS
     * ========================================================================== */
    function escapeHtml(str) {
        if (!str) return '';
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    /* ==========================================================================
     * BOOTSTRAP APPLICATION
     * ========================================================================== */
    document.addEventListener('DOMContentLoaded', () => {
        cacheDom();
        initMatrixCanvas();
        setupNavigation();
        setupMasterLock();
        setupVaultHandlers();
        setupGenerator();
        setupAesVisualizer();
        setupAttackSimulator();
        setupTheoryAccordion();

        // Check if vault already exists in localStorage
        const existing = localStorage.getItem(STORAGE_KEY);
        if (existing) {
            dom.masterStrengthLabel.textContent = 'Existing encrypted vault detected in local storage. Enter password to unlock.';
            dom.masterStrengthLabel.style.color = 'var(--neon-cyan)';
        }
    });

})();
