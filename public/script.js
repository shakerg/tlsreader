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
        await new Promise(resolve => setTimeout(resolve, 3000));

        const response = await fetch(`/results?hostname=${encodeURIComponent(hostname)}`);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        // Display TLS Version
        const tlsVersionElement = document.createElement('div');
        tlsVersionElement.textContent = `TLS Version: ${data.tlsVersion}`;
        tlsVersionElement.classList.add('preferred');
        resultsDiv.appendChild(tlsVersionElement);

        // Display Preferred Cipher
        const preferredCipherElement = document.createElement('div');
        preferredCipherElement.textContent = `Preferred Cipher: ${data.preferredCipher.name}`;
        preferredCipherElement.classList.add('preferred');
        resultsDiv.appendChild(preferredCipherElement);

        // Display TLS 1.0 Availability
        const tls10Element = document.createElement('div');
        tls10Element.textContent = `TLS 1.0 Available: ${data.tls10Available ? 'Yes' : 'No'}`;
        tls10Element.classList.add(data.tls10Available ? 'fail' : 'pass');
        resultsDiv.appendChild(tls10Element);

        // Display TLS 1.1 Availability
        const tls11Element = document.createElement('div');
        tls11Element.textContent = `TLS 1.1 Available: ${data.tls11Available ? 'Yes' : 'No'}`;
        tls11Element.classList.add(data.tls11Available ? 'fail' : 'pass');
        resultsDiv.appendChild(tls11Element);

        // Display Ciphers
        data.ciphers.forEach(result => {
            const resultElement = document.createElement('div');
            resultElement.textContent = `${result.cipher}: ${result.status}`;
            resultElement.classList.add(result.status.toLowerCase());
            resultsDiv.appendChild(resultElement);
        });
    } catch (error) {
        resultsDiv.textContent = `Error: ${error.message}`;
    } finally {
        spinner.style.display = 'none';
    }
}