const tls = require('tls');
const { exec } = require('child_process');

// NOTE: For TLS 1.3 OpenSSL ignores "-cipher". We must use -ciphersuites for TLS 1.3.
// For <= TLS 1.2 we continue to use -cipher.

const DEBUG = process.env.DEBUG_TLS === '1';

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// Helper to run a shell command returning stdout+stderr (no external 'timeout')
function run(cmd, timeoutMs = 12000) {
    return new Promise((resolve) => {
        const child = exec(cmd, { timeout: timeoutMs }, (error, stdout, stderr) => {
            const out = (stdout || '') + (stderr || '');
            if (DEBUG) {
                console.log(`\n[CMD] ${cmd}\n[EXIT] ${error ? error.code : 0}\n`);
            }
            resolve({ error, out });
        });
    });
}

function getTlsResults(hostname) {
    return new Promise((resolve, reject) => {
        const port = 443;
        const results = {
            hostname: hostname,
            preferredProtocol: null,
            preferredCipher: null,
            tlsVersions: {
                'TLS 1.0': { supported: false, ciphers: [], negotiatedCipher: null },
                'TLS 1.1': { supported: false, ciphers: [], negotiatedCipher: null },
                'TLS 1.2': { supported: false, ciphers: [], negotiatedCipher: null },
                'TLS 1.3': { supported: false, ciphers: [], negotiatedCipher: null }
            }
        };

        const options = {
            host: hostname,
            port: port,
            rejectUnauthorized: false
        };

        // Expanded cipher lists (representative but broader; ordering purposeful)
        const cipherSuites = {
            'TLS 1.0': [ 'AES128-SHA', 'AES256-SHA', 'DES-CBC3-SHA' ],
            'TLS 1.1': [ 'AES128-SHA', 'AES256-SHA', 'DES-CBC3-SHA' ],
            'TLS 1.2': [
                // ECDSA (common on large CDNs)
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-ECDSA-CHACHA20-POLY1305',
                'ECDHE-ECDSA-AES128-SHA256',
                'ECDHE-ECDSA-AES256-SHA384',
                'ECDHE-ECDSA-AES128-SHA',
                'ECDHE-ECDSA-AES256-SHA',
                // RSA
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-RSA-CHACHA20-POLY1305',
                'ECDHE-RSA-AES128-SHA256',
                'ECDHE-RSA-AES256-SHA384',
                'ECDHE-RSA-AES128-SHA',
                'ECDHE-RSA-AES256-SHA',
                // Non-PFS fallbacks (should generally be discouraged)
                'AES128-GCM-SHA256',
                'AES256-GCM-SHA384',
                'AES128-SHA256',
                'AES256-SHA256',
                'AES128-SHA',
                'AES256-SHA'
            ],
            'TLS 1.3': [
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256'
            ]
        };

        // Classification rules: simplistic heuristic (can refine)
        function classifyCipher(name) {
            if (!name || name === '(negotiated – unknown)') return 'unknown';
            // Weak indicators
            if (/DES|3DES|RC4|NULL|^AES128-SHA$|AES256-SHA$|AES128-SHA256$|AES256-SHA256$/i.test(name)) return 'weak';
            if (/ECDHE-ECDSA|ECDHE-RSA|CHACHA20|GCM|TLS_AES|POLY1305/i.test(name)) return 'strong';
            return 'moderate';
        }

    if (DEBUG) console.log(`Starting TLS analysis for ${hostname}`);

        // Connect with default settings to get the preferred protocol and cipher
        const socket = tls.connect(options, () => {
            const rawProto = socket.getProtocol();
            // Normalize Node protocol names to our keys
            const protoMap = { 'TLSv1': 'TLS 1.0', 'TLSv1.1': 'TLS 1.1', 'TLSv1.2': 'TLS 1.2', 'TLSv1.3': 'TLS 1.3' };
            results.preferredProtocol = protoMap[rawProto] || rawProto;
            results.preferredCipher = socket.getCipher();
            if (DEBUG) console.log(`Initial connection: ${results.preferredProtocol}, cipher: ${results.preferredCipher.name}`);
            socket.end();

            const orderedVersions = [
                { label: 'TLS 1.0', flag: '-tls1' },
                { label: 'TLS 1.1', flag: '-tls1_1' },
                { label: 'TLS 1.2', flag: '-tls1_2' },
                { label: 'TLS 1.3', flag: '-tls1_3' }
            ];

            // Placeholders; populated inside async block below
            let opensslHasTLS13 = true;
            let clientTLS13Suites = [];

            (async () => {
                // Detect OpenSSL TLS1.3 support and list available TLS1.3 suites for this client build
                try {
                    const suiteList = await run('openssl ciphers -s -v | grep TLSv1.3 || true', 5000);
                    clientTLS13Suites = suiteList.out.split(/\n/)
                        .map(l => (l.match(/^(TLS_[A-Z0-9_]+)/) || [])[1])
                        .filter(Boolean);
                    opensslHasTLS13 = clientTLS13Suites.includes('TLS_AES_128_GCM_SHA256');
                    if (DEBUG) console.log('Client TLS1.3 suites:', clientTLS13Suites.join(','));
                    if (!opensslHasTLS13) {
                        if (DEBUG) console.log('OpenSSL appears to lack TLS 1.3 support, will rely on Node TLS for TLS 1.3 classification.');
                    }
                } catch(_) { opensslHasTLS13 = false; }
                for (const v of orderedVersions) {
                    if (DEBUG) console.log(`\n=== Handshake probe (Node TLS first): ${v.label} ===`);
                    // First try native Node handshake with constrained version
                    let nativeHandshake = false;
                    try {
                        nativeHandshake = await probeWithNodeTLS(hostname, port, v.label);
                    } catch (_) {}
                    if (nativeHandshake) {
                        results.tlsVersions[v.label].supported = true;
                        if (DEBUG) console.log(`Node handshake succeeded for ${v.label}`);
                    }

                    // OpenSSL probe (gives us negotiated cipher line reliably)
                    if (v.label === 'TLS 1.3' && !opensslHasTLS13) {
                        if (DEBUG) console.log('Skipping OpenSSL TLS1.3 probe (unsupported by OpenSSL build).');
                        // If Node handshake succeeded earlier mark supported explicitly
                        if (results.tlsVersions['TLS 1.3'].supported === false && nativeHandshake) {
                            results.tlsVersions['TLS 1.3'].supported = true;
                        }
                    } else {
                        const probeCmd = `openssl s_client -servername ${hostname} -connect ${hostname}:${port} ${v.flag} < /dev/null 2>&1`;
                        const probe = await run(probeCmd, 10000);
                        const negotiatedCipher = (probe.out.match(/Cipher\s*:\s*([^\s\r\n]+)/) || [])[1];
                        const protocol = (probe.out.match(/Protocol\s*:\s*([^\s\r\n]+)/) || [])[1];
                        const protoMap = { 'TLSv1': 'TLS 1.0', 'TLSv1.1': 'TLS 1.1', 'TLSv1.2': 'TLS 1.2', 'TLSv1.3': 'TLS 1.3' };
                        const mapped = protoMap[protocol];
                        const handshakeSuccess = !!mapped; // only if a protocol line parsed
                        if (handshakeSuccess && mapped === v.label) {
                            results.tlsVersions[v.label].supported = true;
                            if (negotiatedCipher && negotiatedCipher !== '0000') {
                                results.tlsVersions[v.label].negotiatedCipher = negotiatedCipher;
                                // Store negotiated cipher for later integration (don't add to results yet to avoid interfering with enumeration)
                            } else if (v.label === 'TLS 1.3' && !negotiatedCipher) {
                                // Store that we had a successful handshake but unknown cipher
                                results.tlsVersions[v.label].negotiatedCipher = '(negotiated – unknown)';
                            }
                        } else if (DEBUG) {
                            console.log(`${v.label} OpenSSL probe failed or negotiated different version: parsed='${protocol}' mapped='${mapped}' expected='${v.label}'`);
                        }
                    }

                    // Enumerate test ciphers (always attempt for 1.2 & 1.3, conditional for legacy)
                    const testList = cipherSuites[v.label];
                    for (const cipher of testList) {
                        if (v.label === 'TLS 1.3') {
                            if (!opensslHasTLS13) {
                                results.tlsVersions[v.label].ciphers.push({ cipher, status: 'Not Tested', details: 'OpenSSL TLS1.3 unsupported', strength: undefined });
                                continue;
                            }
                            if (!clientTLS13Suites.includes(cipher)) {
                                results.tlsVersions[v.label].ciphers.push({ cipher, status: 'Not Tested', details: 'Suite not supported by client OpenSSL build', strength: undefined });
                                continue;
                            }
                            // Delay between TLS1.3 tests to avoid session resumption / ticket reuse influencing results
                            await sleep(600);
                        }
                        const cipherResult = await testCipher(hostname, port, cipher, v.flag, v.label === 'TLS 1.3', true);
                        results.tlsVersions[v.label].ciphers.push(cipherResult);
                    }

                    // Mark support if any cipher succeeded
                    if (!results.tlsVersions[v.label].supported) {
                        results.tlsVersions[v.label].supported = results.tlsVersions[v.label].ciphers.some(c => c.status === 'Supported');
                    }
                }
                // Integrate preferred negotiated cipher into appropriate version
                if (results.preferredProtocol && results.tlsVersions[results.preferredProtocol]) {
                    const verObj = results.tlsVersions[results.preferredProtocol];
                    verObj.supported = true;
                    if (results.preferredCipher && results.preferredCipher.name) {
                        const name = results.preferredCipher.name;
                        const existing = verObj.ciphers.find(c => c.cipher === name);
                        if (!existing) {
                            verObj.ciphers.unshift({ cipher: name, status: 'Supported', details: 'Negotiated (initial handshake)', strength: classifyCipher(name) });
                        } else if (existing.status !== 'Supported') {
                            existing.status = 'Supported';
                            existing.details = 'Negotiated (initial handshake)';
                            existing.strength = classifyCipher(existing.cipher);
                        }
                    }
                }

                // Also integrate per-version negotiated ciphers from probes
                for (const [ver, data] of Object.entries(results.tlsVersions)) {
                    if (data.negotiatedCipher && data.negotiatedCipher !== '(negotiated – unknown)') {
                        const existing = data.ciphers.find(c => c.cipher === data.negotiatedCipher);
                        if (!existing) {
                            data.ciphers.unshift({ cipher: data.negotiatedCipher, status: 'Supported', details: 'Negotiated (probe)', strength: classifyCipher(data.negotiatedCipher) });
                        }
                    } else if (data.negotiatedCipher === '(negotiated – unknown)') {
                        const existing = data.ciphers.find(c => c.cipher === '(negotiated – unknown)');
                        if (!existing) {
                            data.ciphers.unshift({ cipher: '(negotiated – unknown)', status: 'Supported', details: 'Negotiated (probe)', strength: 'unknown' });
                        }
                    }
                }

                // TLS1.3 fallback classification if Node succeeded but OpenSSL failed
                if (results.preferredProtocol === 'TLS 1.3') {
                    const t13 = results.tlsVersions['TLS 1.3'];
                    if (t13 && !t13.ciphers.some(c => c.status === 'Supported')) {
                        t13.ciphers.unshift({ cipher: results.preferredCipher ? results.preferredCipher.name : '(negotiated – unknown)', status: 'Supported', details: 'Negotiated (initial handshake)', strength: classifyCipher(results.preferredCipher ? results.preferredCipher.name : '') });
                        t13.ciphers = t13.ciphers.map(c => c.status === 'Not Supported' ? { ...c, status: 'Not Tested', details: c.details === 'Connection failed' ? 'OpenSSL probe issue' : c.details } : c);
                        t13.supported = true;
                    }
                }

                // Demote TLS 1.0 / 1.1 if they show supported but have no Supported cipher entries
                for (const legacy of ['TLS 1.0','TLS 1.1']) {
                    const obj = results.tlsVersions[legacy];
                    if (obj.supported && !obj.ciphers.some(c => c.status === 'Supported')) {
                        obj.supported = false; // no direct handshake evidence
                    }
                }

                // (Recheck logic removed in favor of strict per-cipher single-offer testing.)

                // TLS 1.3 elimination scan to discover all server-supported suites
                const t13List = cipherSuites['TLS 1.3'];
                const discovered = new Set();
                if (opensslHasTLS13 && t13List && t13List.length) {
                    // Start with full list, then remove negotiated cipher each iteration
                    let remaining = [...t13List];
                    let guard = 0;
                    while (remaining.length && guard < 10) {
                        guard++;
                        const offerLine = remaining.join(':');
                        const cmd = `openssl s_client -servername ${hostname} -connect ${hostname}:443 -tls1_3 -ciphersuites ${offerLine} < /dev/null 2>&1`;
                        const attempt = await run(cmd, 8000);
                        const chosen = (attempt.out.match(/Cipher\s*(?:is|:)\s*([^\s\r\n]+)/) || [])[1];
                        const proto = (attempt.out.match(/Protocol\s*:\s*([^\s\r\n]+)/) || [])[1];
                        if (proto && proto.includes('TLSv1.3') && chosen && chosen !== '0000' && t13List.includes(chosen)) {
                            discovered.add(chosen);
                            // Remove chosen and iterate to find others
                            remaining = remaining.filter(c => c !== chosen);
                            if (DEBUG) console.log(`[ELIMINATION][TLS1.3] discovered ${chosen}; remaining=${remaining.join(',')}`);
                        } else {
                            // If we cannot negotiate further, break
                            break;
                        }
                    }
                }

                // Apply elimination discoveries to TLS 1.3 cipher statuses
                if (discovered.size) {
                    const t13 = results.tlsVersions['TLS 1.3'];
                    for (const suite of discovered) {
                        const entry = t13.ciphers.find(c => c.cipher === suite);
                        if (entry) {
                            if (entry.status !== 'Supported') {
                                entry.status = 'Supported';
                                entry.details = entry.details && entry.details.startsWith('Negotiated') ? entry.details : 'Supported (elimination scan)';
                                entry.strength = classifyCipher(entry.cipher);
                            }
                        } else {
                            t13.ciphers.unshift({ cipher: suite, status: 'Supported', details: 'Supported (elimination scan)', strength: classifyCipher(suite) });
                        }
                    }
                    t13.supported = true;
                }

                resolve(results);
            })().catch(err => {
                if (DEBUG) console.error('TLS analysis error:', err);
                resolve(results);
            });
        });

        socket.on('error', (err) => {
            console.error('Initial connection error:', err.message);
            reject(err);
        });
    });
}

function testCipher(hostname, port, cipher, flag, isTLS13, strictTLS13 = false) {
    return new Promise(async (resolve) => {
        const cipherArg = isTLS13 ? `-ciphersuites ${cipher}` : `-cipher ${cipher}`;
        const cmd = `openssl s_client -servername ${hostname} -connect ${hostname}:${port} ${flag} ${cipherArg} < /dev/null 2>&1`;
        const { error, out } = await run(cmd, 10000);
        const negotiatedCipher = (out.match(/Cipher\s*(?:is|:)\s*([^\s\r\n]+)/) || [])[1];
        const protocol = (out.match(/Protocol\s*:\s*([^\s\r\n]+)/) || [])[1];
        const alertMatch = out.match(/alert ([a-zA-Z_ ]+):/);
        const connected = out.includes('CONNECTED(') || !!protocol;

        let status = 'Not Supported';
        let details = '';

        if (connected && negotiatedCipher) {
            // Additional guard: ensure protocol actually matches the requested legacy version.
            if (!isTLS13) {
                const expected = flag === '-tls1' ? 'TLSv1' : (flag === '-tls1_1' ? 'TLSv1.1' : (flag === '-tls1_2' ? 'TLSv1.2' : null));
                if (expected && protocol && protocol !== expected) {
                    // OpenSSL printed a different protocol (often TLSv1.3 placeholder) meaning handshake for requested version failed.
                    resolve({ cipher, status: 'Not Supported', details: 'Version not negotiated', strength: undefined });
                    return;
                }
            }
            if (negotiatedCipher === '0000' || negotiatedCipher === '(NONE)') {
                status = 'Not Supported';
                details = 'Handshake failure (no cipher)';
            } else if (negotiatedCipher === cipher || (isTLS13 && !strictTLS13)) {
                status = 'Supported';
                details = protocol || 'Supported';
            } else {
                // For legacy versions, a different cipher or placeholder indicates failure for forced single-cipher attempt
                if (!isTLS13) {
                    status = 'Not Supported';
                    details = negotiatedCipher === '(NONE)' ? 'No legacy support' : `Server chose different cipher (${negotiatedCipher})`;
                } else {
                    status = 'Supported';
                    details = `Negotiated different: ${negotiatedCipher}`;
                }
            }
        } else if (error && error.killed) {
            status = 'Timeout';
            details = 'Exec timeout';
        } else if (out.includes('no shared cipher') || out.includes('no cipher match')) {
            status = 'Not Supported';
            details = 'No shared cipher';
        } else if (out.match(/handshake failure/i)) {
            status = 'Not Supported';
            details = 'Handshake failure';
        } else if (alertMatch) {
            status = 'Not Supported';
            details = `Alert: ${alertMatch[1].trim()}`;
        } else if (!connected) {
            status = 'Not Supported';
            details = 'Connection failed';
        }

        // TLS 1.3 hybrid strategy: try multi-cipher offer if single-cipher fails
        if (isTLS13 && strictTLS13 && status === 'Not Supported') {
            const allSuites = ['TLS_AES_128_GCM_SHA256','TLS_AES_256_GCM_SHA384','TLS_CHACHA20_POLY1305_SHA256'];
            // Test with cipher first in list, then all others
            const offerLine = [cipher, ...allSuites.filter(s => s !== cipher)].join(':');
            const retryCmd = `openssl s_client -servername ${hostname} -connect ${hostname}:${port} -tls1_3 -ciphersuites ${offerLine} < /dev/null 2>&1`;
            const retry = await run(retryCmd, 10000);
            const rCipher = (retry.out.match(/Cipher\s*(?:is|:)\s*([^\s\r\n]+)/) || [])[1];
            const rProto = (retry.out.match(/Protocol\s*:\s*([^\s\r\n]+)/) || [])[1];
            
            if (rProto && rProto.includes('TLSv1.3') && rCipher && rCipher !== '0000') {
                if (rCipher === cipher) {
                    status = 'Supported';
                    details = 'Supported (in cipher list)';
                } else {
                    // Try a forced reorder attempt
                    const forceCmd = `openssl s_client -servername ${hostname} -connect ${hostname}:${port} -tls1_3 -ciphersuites ${cipher}:${allSuites.filter(s => s !== cipher).reverse().join(':')} < /dev/null 2>&1`;
                    const force = await run(forceCmd, 10000);
                    const fCipher = (force.out.match(/Cipher\s*(?:is|:)\s*([^\s\r\n]+)/) || [])[1];
                    const fProto = (force.out.match(/Protocol\s*:\s*([^\s\r\n]+)/) || [])[1];
                    if (fProto && fProto.includes('TLSv1.3') && fCipher === cipher) {
                        status = 'Supported';
                        details = 'Supported (reordered list)';
                    } else {
                        status = 'Not Negotiated';
                        details = `Server always negotiates ${rCipher} (single-cipher ${cipher} failed)`;
                    }
                }
            }
        }

        if (DEBUG && status !== 'Supported') {
            console.log(`[DEBUG][${cipher}] Failure summary: ${details}`);
            console.log(out.split('\n').slice(0, 12).join('\n'));
        }

        // Reuse classification logic (duplicated minimal version to avoid hoist issues)
        function classifyCipherLocal(name) {
            if (!name) return 'unknown';
            if (/DES|3DES|RC4|NULL|^AES128-SHA$|AES256-SHA$|AES128-SHA256$|AES256-SHA256$/i.test(name)) return 'weak';
            if (/ECDHE-ECDSA|ECDHE-RSA|CHACHA20|GCM|TLS_AES|POLY1305/i.test(name)) return 'strong';
            return 'moderate';
        }
        resolve({ cipher, status, details, strength: status === 'Supported' ? classifyCipherLocal(cipher) : undefined });
    });
}

// Native Node TLS probe forcing single version
function probeWithNodeTLS(host, port, label) {
    return new Promise((resolve) => {
        const map = { 'TLS 1.0': 'TLSv1', 'TLS 1.1': 'TLSv1.1', 'TLS 1.2': 'TLSv1.2', 'TLS 1.3': 'TLSv1.3' };
        const ver = map[label];
        if (!ver) return resolve(false);
        const s = tls.connect({ host, port, servername: host, minVersion: ver, maxVersion: ver, rejectUnauthorized: false }, () => {
            s.end();
            resolve(true);
        });
        s.on('error', () => resolve(false));
        setTimeout(() => { try { s.destroy(); } catch(_){}; resolve(false); }, 6000);
    });
}

module.exports = { getTlsResults };