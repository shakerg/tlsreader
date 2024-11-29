const tls = require('tls');
const { exec } = require('child_process');

function getTlsResults(hostname) {
    return new Promise((resolve, reject) => {
        const port = 443;
        const options = {
            host: hostname,
            port: port,
            rejectUnauthorized: false
        };

        const socket = tls.connect(options, () => {
            const tlsVersion = socket.getProtocol();
            const preferredCipher = socket.getCipher();
            socket.end();

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

            const results = [];
            let completed = 0;

            ciphers.forEach(cipher => {
                const command = `openssl s_client -connect ${hostname}:${port} -cipher '${cipher}' -tls1_2 < /dev/null`;

                exec(command, (error, stdout, stderr) => {
                    // Parse the stdout to check if the cipher was successful
                    const cipherRegex = /Cipher\s*:\s*(.*)/;
                    const match = stdout.match(cipherRegex);

                    if (match && match[1].trim() === cipher) {
                        results.push({ cipher, status: 'Pass' });
                    } else {
                        results.push({ cipher, status: 'Fail' });
                    }

                    completed++;
                    if (completed === ciphers.length) {
                        resolve({ tlsVersion, preferredCipher, results });
                    }
                });
            });
        });

        socket.on('error', (err) => {
            reject(err);
        });
    });
}

module.exports = { getTlsResults };