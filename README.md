# TLS Inspector

TLS Inspector is a Node.js application that provides TLS certificate inspection through a web interface. It allows users to enter a hostname and retrieve its TLS certificate details, including the supported TLS versions and cipher suites.

## Project Structure

- `server.js`: The main server file that sets up the Express server and defines routes.
- `tlsreader.js`: Module that retrieves TLS certificate information and tests supported ciphers for a given hostname.
- `public/`:
  - `index.html`: Front-end interface for users to input hostnames and view results.

## Prerequisites

- [Node.js](https://nodejs.org/) installed.
- OpenSSL installed and accessible from the command line.

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/tls-inspector.git
   cd tls-inspector
    ```
2. **Install dependencies**

   ```bash
   npm install
   ```
3. **Start the server**

   ```bash
    node server.js
    ```
4. **Access the application**

   Open a web browser and navigate to `http://localhost:3000`.

## Usage

1. Enter a hostname in the input field.
2. Click the Run button to retrieve and display the TLS certificate details.

Features:
- TLS Version Detection: Identifies the TLS version supported by the server.
- Preferred Cipher: Displays the server's preferred cipher suite.
- TLS 1.0 and TLS 1.1 Availability Check: Verifies if the server supports the outdated TLS 1.0 and TLS 1.1 protocols and highlights if they are available.
- Cipher Suite Testing: Tests a list of known TLS 1.2 and TLS 1.3 cipher suites and reports which ones are supported (Pass) or not (Fail).

## API Endpoints
- GET /results?hostname=<hostname>: Returns TLS certificate information, TLS 1.0 and TLS 1.1 availability, and cipher test results for the specified hostname.

## Example
`curl http://localhost:3000/results?hostname=www.example.com`

## Response
```
{
  "tlsVersion": "TLSv1.2",
  "preferredCipher": {
    "name": "ECDHE-RSA-AES128-GCM-SHA256",
    "version": "TLSv1/SSLv3",
    "standardName": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  },
  "tls10Available": false,
  "tls11Available": false,
  "ciphers": [
    {
      "cipher": "TLS_AES_128_GCM_SHA256",
      "status": "Fail"
    },
    {
      "cipher": "TLS_AES_256_GCM_SHA384",
      "status": "Fail"
    },
    {
      "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
      "status": "Pass"
    },
    {
      "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
      "status": "Pass"
    }
    // Additional cipher results...
  ]
}
```

## Files
- server.js: Sets up the Express server, serves static files, and handles the /results endpoint.
- tlsreader.js: Contains the getTlsResults(hostname) function to fetch TLS data, check TLS 1.0 and 1.1 availability, and test cipher suites.
- public/index.html: Front-end interface for users to input hostnames and view results, displaying TLS versions, cipher support, and TLS 1.0/1.1 availability.

## Dependencies
- express: Web framework for Node.js.
- child_process: Module for spawning child processes to run OpenSSL commands.
- tls: Module for creating TLS/SSL servers and clients.
