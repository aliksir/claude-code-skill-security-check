#!/usr/bin/env node
import('./bin/install.mjs').catch(e => { console.error(e); process.exit(1); });
