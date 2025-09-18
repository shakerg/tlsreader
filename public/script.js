document.getElementById('runButton').addEventListener('click', runTest);

async function runTest() {
    const hostnameInput = document.getElementById('hostname');
    const hostname = hostnameInput.value.trim();
    hostnameInput.value = hostname;

    const spinner = document.getElementById('spinner');
    const resultsDiv = document.getElementById('results');

    if (!hostname) {
        alert('Please enter a hostname');
        return;
    }

    spinner.style.display = 'block';
    resultsDiv.innerHTML = '';

    try {
        const response = await fetch(`/results?hostname=${encodeURIComponent(hostname)}`);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        // Create main results container
        const container = document.createElement('div');
        container.classList.add('results-container');

        // Header section
        const header = document.createElement('div');
        header.classList.add('header-section');
        header.innerHTML = `
            <h2>TLS Analysis Report for ${data.hostname}</h2>
            <div class="summary">
                <div class="summary-item">
                    <span class="label">Preferred Protocol:</span>
                    <span class="value preferred">${data.preferredProtocol}</span>
                </div>
                <div class="summary-item">
                    <span class="label">Preferred Cipher:</span>
                    <span class="value preferred">${data.preferredCipher.name}</span>
                </div>
            </div>
        `;
        container.appendChild(header);

        // TLS Versions Overview
        const overview = document.createElement('div');
        overview.classList.add('overview-section');
        overview.innerHTML = '<h3>TLS Protocol Support Overview</h3>';
        
        const overviewGrid = document.createElement('div');
        overviewGrid.classList.add('overview-grid');

        Object.entries(data.tlsVersions).forEach(([version, info]) => {
            const versionCard = document.createElement('div');
            versionCard.classList.add('version-card');
            versionCard.classList.add(info.supported ? 'supported' : 'not-supported');
            
            const securityClass = getSecurityClass(version, info.supported);
            versionCard.classList.add(securityClass);

            const supportedCiphers = info.ciphers.filter(c => c.status === 'Supported').length;
            const totalCiphers = info.ciphers.length;

            versionCard.innerHTML = `
                <h4>${version}</h4>
                <div class="status">${info.supported ? 'Supported' : 'Not Supported'}</div>
                <div class="cipher-count">${supportedCiphers}/${totalCiphers} ciphers</div>
                ${getSecurityIndicator(version, info.supported)}
            `;
            overviewGrid.appendChild(versionCard);
        });

        overview.appendChild(overviewGrid);
        container.appendChild(overview);

        // Detailed cipher results by TLS version (show if any ciphers attempted)
        Object.entries(data.tlsVersions).forEach(([version, info]) => {
            if (info.ciphers.length > 0) {
                const section = document.createElement('div');
                section.classList.add('cipher-section');
                
                const sectionHeader = document.createElement('h3');
                sectionHeader.textContent = `${version} Cipher Suites` + (info.supported ? '' : ' (disabled / not negotiated)');
                sectionHeader.classList.add(getSecurityClass(version, info.supported));
                section.appendChild(sectionHeader);

                const table = document.createElement('table');
                table.classList.add('cipher-table');
                
                const headerRow = document.createElement('tr');
                headerRow.innerHTML = `
                    <th>Cipher Suite</th>
                    <th>Status</th>
                    <th>Strength</th>
                    <th>Details</th>
                `;
                table.appendChild(headerRow);

                info.ciphers.forEach(cipher => {
                    const row = document.createElement('tr');
                    row.classList.add(cipher.status.toLowerCase().replace(/\s+/g, '-'));
                    if (cipher.strength) {
                        row.classList.add(`strength-${cipher.strength}`);
                    }
                    
                    row.innerHTML = `
                        <td class="cipher-name">${cipher.cipher}</td>
                        <td class="status">${cipher.status}</td>
                        <td class="strength">${cipher.status === 'Supported' && cipher.strength ? cipher.strength : ''}</td>
                        <td class="details">${cipher.details || ''}</td>
                    `;
                    table.appendChild(row);
                });

                section.appendChild(table);
                container.appendChild(section);
            }
        });

        resultsDiv.appendChild(container);

    } catch (error) {
        resultsDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    } finally {
        spinner.style.display = 'none';
    }
}

function getSecurityClass(version, supported) {
    if (!supported) {
        if (version === 'TLS 1.3') return 'poor';
        return 'neutral';
    }
    switch (version) {
        case 'TLS 1.0':
        case 'TLS 1.1':
            return 'warning';
        case 'TLS 1.2':
            return 'good';
        case 'TLS 1.3':
            return 'excellent';
        default:
            return 'neutral';
    }
}

function getSecurityIndicator(version, supported) {
    if (!supported) {
        if (version === 'TLS 1.3') return '<div class="security-note poor">✗ Poor (not supported)</div>';
        return '<div class="security-note">✓ Good (disabled)</div>';
    }
    switch (version) {
        case 'TLS 1.0':
        case 'TLS 1.1':
            return '<div class="security-note warning">⚠ Deprecated</div>';
        case 'TLS 1.2':
            return '<div class="security-note">✓ Secure</div>';
        case 'TLS 1.3':
            return '<div class="security-note excellent">★ Excellent</div>';
        default:
            return '';
    }
}