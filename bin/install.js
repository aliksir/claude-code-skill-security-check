#!/usr/bin/env node
/**
 * claude-code-skill-security-check installer
 *
 * Installs SKILL.md, hooks, semgrep-rules, IAM templates, and updater
 * to the appropriate ~/.claude/ directories.
 *
 * Usage: npx claude-code-skill-security-check
 */

import { copyFileSync, mkdirSync, existsSync, readdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PKG_ROOT = join(__dirname, "..");

const HOME = process.env.HOME || process.env.USERPROFILE;
if (!HOME) {
  console.error("Error: Could not determine home directory");
  process.exit(1);
}

const CLAUDE_DIR = join(HOME, ".claude");
const TARGETS = {
  skill: join(CLAUDE_DIR, "skills", "skill-security-check"),
  hooks: join(CLAUDE_DIR, "hooks"),
  semgrep: join(CLAUDE_DIR, "semgrep-rules"),
  iam: join(CLAUDE_DIR, "iam-policy-template"),
  updater: join(CLAUDE_DIR, "updater"),
};

const FORCE = process.argv.includes("--force");

function copyDir(srcDir, destDir) {
  if (!existsSync(srcDir)) return;
  mkdirSync(destDir, { recursive: true });
  const files = readdirSync(srcDir);
  for (const file of files) {
    const srcPath = join(srcDir, file);
    const destPath = join(destDir, file);
    if (existsSync(destPath) && !FORCE) {
      console.log(`  [skip] ${file} (already exists)`);
      continue;
    }
    copyFileSync(srcPath, destPath);
    console.log(FORCE && existsSync(destPath) ? `  [overwrite] ${file}` : `  [copy] ${file}`);
  }
}

function main() {
  console.log("");
  console.log("=== Claude Code Skill Security Check — Installer ===");
  console.log("");

  // 1. SKILL.md
  console.log("[1/5] SKILL.md → skills/skill-security-check/");
  mkdirSync(TARGETS.skill, { recursive: true });
  const skillSrc = join(PKG_ROOT, "SKILL.md");
  const skillDest = join(TARGETS.skill, "SKILL.md");
  if (existsSync(skillDest) && !FORCE) {
    console.log("  [skip] SKILL.md (already exists — run with --force to overwrite)");
  } else {
    copyFileSync(skillSrc, skillDest);
    console.log(FORCE ? "  [overwrite] SKILL.md" : "  [copy] SKILL.md");
  }

  // 2. Hooks
  console.log("[2/5] hooks/ → ~/.claude/hooks/");
  copyDir(join(PKG_ROOT, "hooks"), TARGETS.hooks, "hooks");

  // 3. Semgrep rules
  console.log("[3/5] semgrep-rules/ → ~/.claude/semgrep-rules/");
  copyDir(join(PKG_ROOT, "semgrep-rules"), TARGETS.semgrep, "semgrep-rules");

  // 4. IAM templates
  console.log("[4/5] iam-policy-template/ → ~/.claude/iam-policy-template/");
  copyDir(join(PKG_ROOT, "iam-policy-template"), TARGETS.iam, "iam-policy-template");

  // 5. Updater
  console.log("[5/5] updater/ → ~/.claude/updater/");
  copyDir(join(PKG_ROOT, "updater"), TARGETS.updater, "updater");

  console.log("");
  console.log("Done! Use /skill-security-check in Claude Code to run a scan.");
  console.log("");
  console.log("Optional: Install the CLI scanner for deeper analysis:");
  console.log("  pip install skill-scanner");
  console.log("");
}

main();
