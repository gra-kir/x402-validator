'use strict';
const express = require('express');
const validateRouter = require('./validate-router');

const PORT = process.env.PORT || 3000;
const app  = express();

app.use('/validate', validateRouter);

// Redirect bare root to the UI
app.get('/', (req, res) => res.redirect('/validate'));

app.listen(PORT, () => {
  console.log(`x402 validator running on http://localhost:${PORT}/validate`);
});
