const tls = require('tls');
const { execFile } = require('child_process');

function getTlsResults(hostname) {
    return new Promise((resolve, reject) => {
        const port = 443;
        const results = {
            tlsVersion: null,
            preferredCipher: null,
            tls10Available: false,
            tls11Available: false,
            ciphers: []
        };

        const options = {
            host: hostname,
            port: port,
            rejectUnauthorized: false
        };

        // Connect with default settings to get the current TLS version and preferred cipher
        const socket = tls.connect(options, () => {
            results.tlsVersion = socket.getProtocol();
            results.preferredCipher = socket.getCipher();
            socket.end();

            // Function to test specific TLS versions
            function testTlsVersion(protocol, versionName, callback) {
                const tlsOptions = {
                    host: hostname,
                    port: port,
                    rejectUnauthorized: false,
                    minVersion: protocol,
                    maxVersion: protocol
                };
                const testSocket = tls.connect(tlsOptions, () => {
                    if (versionName === 'TLS 1.0') {
                        results.tls10Available = true;
                    } else if (versionName === 'TLS 1.1') {
                        results.tls11Available = true;
                    }
                    testSocket.end();
                    callback();
                });
                testSocket.on('error', () => {
                    callback();
                });
            }

            // Test TLS 1.0
            testTlsVersion('TLSv1', 'TLS 1.0', () => {
                // Test TLS 1.1
                testTlsVersion('TLSv1.1', 'TLS 1.1', () => {
                    // Proceed to test ciphers after TLS version checks
                    const ciphers = [
                        // TLS 1.3 ciphers
                        'TLS_AES_128_GCM_SHA256',
                        'TLS_AES_256_GCM_SHA384',
                        'TLS_CHACHA20_POLY1305_SHA256',
                        'TLS_AES_128_CCM_SHA256',
                        'TLS_AES_128_CCM_8_SHA256',
                        // TLS 1.2 ciphers
                        'ECDHE-RSA-AES128-GCM-SHA256',
                        'ECDHE-RSA-AES256-GCM-SHA384',
                        'ECDHE-RSA-AES128-SHA256',
                        'ECDHE-RSA-AES256-SHA384',
                        'ECDHE-RSA-AES128-SHA',
                        'ECDHE-RSA-AES256-SHA',
                        'AES128-GCM-SHA256',
                        'AES256-GCM-SHA384',
                        'AES128-SHA256',
                        'AES256-SHA256',
                        'AES128-SHA',
                        'AES256-SHA'
                    ];

                    let completed = 0;

                    ciphers.forEach(cipher => {
                        const tlsVersionFlag = cipher.startsWith('TLS_') ? '-tls1_3' : '-tls1_2';
                        const args = ['s_client', '-connect', `${hostname}:${port}`, '-cipher', cipher, tlsVersionFlag, '<', '/dev/null'];

                        execFile('openssl', args, (error, stdout, stderr) => {
                            // Parse the stdout to check if the cipher was successful
                            const cipherRegex = /Cipher\s*:\s*(.*)/;
                            const match = stdout.match(cipherRegex);

                            if (match && match[1].trim() === cipher) {
                                results.ciphers.push({ cipher, status: 'Pass' });
                            } else {
                                results.ciphers.push({ cipher, status: 'Fail' });
                            }

                            completed++;
                            if (completed === ciphers.length) {
                                resolve(results);
                            }
                        });
                    });
                });
            });
        });

        socket.on('error', (err) => {
            reject(err);
        });
    });
}

module.exports = { getTlsResults };