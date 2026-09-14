#!/usr/bin/env node
/* build.js — inline every script and stylesheet into one HTML file.
 * The split version is for working on; the bundle is for putting on
 * a phone, where one file is far easier to move around than nine.
 *
 *   node build.js   ->   dist/lockingvault.html
 */
const fs = require('fs');
const path = require('path');

const root = __dirname;
let html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');

// stylesheet
html = html.replace(/<link rel="stylesheet" href="([^"]+)">/g, (_, href) =>
  '<style>\n' + fs.readFileSync(path.join(root, href), 'utf8') + '</style>');

// scripts, in the order index.html declares them
html = html.replace(/<script src="([^"]+)"><\/script>/g, (_, src) =>
  '<script>\n' + fs.readFileSync(path.join(root, src), 'utf8') + '</script>');

if (/<script src=|<link rel="stylesheet"/.test(html)) {
  console.error('Something did not inline — check the paths in index.html');
  process.exit(1);
}

fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
const out = path.join(root, 'dist', 'lockingvault.html');
fs.writeFileSync(out, html);
console.log('dist/lockingvault.html  ' + Math.round(html.length / 1024) + ' KB');
