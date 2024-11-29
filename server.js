const express = require('express');
const tlsReader = require('./tlsreader');
const app = express();
const port = 3000;

app.use(express.static('public'));

app.get('/results', async (req, res) => {
    const hostname = req.query.hostname;
    if (!hostname) {
        res.status(400).send('Hostname is required');
        return;
    }

    try {
        const results = await tlsReader.getTlsResults(hostname); 
        res.json(results);
    } catch (error) {
        res.status(500).send('Error retrieving TLS results');
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});