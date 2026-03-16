#!/usr/bin/env node
import('./install.mjs').catch(e => { console.error(e); process.exit(1); });
