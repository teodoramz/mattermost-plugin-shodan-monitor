// Copies the hand-written plugin bundle into dist/ (no transpiling needed).
const fs = require('fs');
const path = require('path');

const src = path.join(__dirname, 'src', 'index.js');
const outDir = path.join(__dirname, 'dist');
fs.mkdirSync(outDir, {recursive: true});
fs.copyFileSync(src, path.join(outDir, 'main.js'));
console.log('webapp built: dist/main.js');
