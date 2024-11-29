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
2. Click the "Inspect" button.
3. View the certificate details, supported TLS versions, and cipher suites.


