'use strict';
// Vercel function fallback: re-export the same bare handler as server.js.
// The config property travels with the function object (set in server.js).
module.exports = require('../server.js');
