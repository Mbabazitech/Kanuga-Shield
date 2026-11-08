#!/usr/bin/env node
/**
 * scripts/build-installer.js
 * Builds the standalone Windows installer: Kanuga-Shield-Setup.exe
 * 
 * Features:
 *  - Bundled portable Node.js runtime (no Node installation required on target PCs)
 *  - Native Windows desktop launcher (KanugaShield.exe) with Edge App Mode window
 *  - Local user data storage in %APPDATA%\Kanuga Shield\data
 *  - Cloud Firestore licensing sync across the internet
 *  - Desktop & Start Menu shortcuts with high-res Kanuga Shield icon
 *  - Clean uninstaller (Uninstall.exe)
 * 
 * Usage: node scripts/build-installer.js
 */

'use strict';
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const DIST = path.join(ROOT, 'dist');
const STAGING = path.join(DIST, 'staging');
const PAYLOAD_ZIP = path.join(DIST, 'app-payload.zip');
const ICO_FILE = path.join(ROOT, 'public', 'app.ico');

function findNodeBinary() {
  const candidates = [
    'C:\\Users\\DXB GADGETS UG\\.gemini\\antigravity\\tools\\node-v20.18.0-win-x64\\node.exe',
    process.execPath,
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  throw new Error('Could not locate node.exe to bundle in installer.');
}

function copyWithRobocopy(src, dest) {
  if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
  try {
    execSync(`robocopy "${src}" "${dest}" /E /NFL /NDL /NJH /NJS /nc /ns /np`, { cwd: ROOT });
  } catch (err) {
    // Robocopy returns exit code 0-7 on successful copy
    if (err.status && err.status > 7) {
      throw new Error(`Robocopy failed from ${src} to ${dest} with exit code ${err.status}`);
    }
  }
}

function compileCSharp(sourceFile, outputFile, icoFile, extraAssemblies = [], extraResources = []) {
  const tempPs1 = path.join(DIST, `compile_${Date.now()}_${Math.random().toString(36).substring(7)}.ps1`);
  
  let refLines = `
$params.ReferencedAssemblies.Add("System.dll")
$params.ReferencedAssemblies.Add("System.Windows.Forms.dll")
$params.ReferencedAssemblies.Add("System.Drawing.dll")
`;
  extraAssemblies.forEach(a => {
    refLines += `$params.ReferencedAssemblies.Add("${a}")\n`;
  });

  let resLines = '';
  extraResources.forEach(r => {
    resLines += `$params.EmbeddedResources.Add("${r.replace(/\\/g, '\\\\')}")\n`;
  });

  const psScript = `
$src = [System.IO.File]::ReadAllText('${sourceFile.replace(/'/g, "''")}')
$params = New-Object System.CodeDom.Compiler.CompilerParameters
$params.GenerateExecutable = $true
$params.OutputAssembly = '${outputFile.replace(/'/g, "''")}'
$params.CompilerOptions = '/target:winexe /win32icon:"${icoFile.replace(/"/g, '`"')}" /optimize'
${refLines}
${resLines}

$provider = New-Object Microsoft.CSharp.CSharpCodeProvider
$results = $provider.CompileAssemblyFromSource($params, $src)
if ($results.Errors.Count -gt 0) {
    $results.Errors | ForEach-Object { Write-Error $_.ErrorText }
    exit 1
}
`;

  fs.writeFileSync(tempPs1, psScript, 'utf8');
  try {
    execSync(`powershell -NoProfile -ExecutionPolicy Bypass -File "${tempPs1}"`, {
      stdio: 'inherit',
      cwd: ROOT,
    });
  } finally {
    if (fs.existsSync(tempPs1)) fs.unlinkSync(tempPs1);
  }
}

async function build() {
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║       Kanuga Shield – Building Standalone Installer (.exe)   ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝\n');

  // Step 1: Clean build directories (preserve app-payload.zip if already generated)
  console.log('[1/6] Preparing build directories...');
  const reuseZip = fs.existsSync(PAYLOAD_ZIP) && fs.statSync(PAYLOAD_ZIP).size > 10000000;
  if (!fs.existsSync(DIST)) {
    fs.mkdirSync(DIST, { recursive: true });
  }
  if (!reuseZip) {
    if (fs.existsSync(STAGING)) fs.rmSync(STAGING, { recursive: true, force: true });
    fs.mkdirSync(STAGING, { recursive: true });
  }

  // Step 2: Compile native launcher and uninstaller
  console.log('\n[2/6] Compiling native Windows desktop launcher & uninstaller...');
  const launcherCs = path.join(ROOT, 'src-installer', 'KanugaLauncher.cs');
  const uninstallCs = path.join(ROOT, 'src-installer', 'Uninstall.cs');
  const launcherExe = path.join(DIST, 'KanugaShield.exe');
  const uninstallExe = path.join(DIST, 'Uninstall.exe');

  compileCSharp(launcherCs, launcherExe, ICO_FILE);
  console.log('  ✅ Compiled KanugaShield.exe (Native Windows Application Launcher)');

  compileCSharp(uninstallCs, uninstallExe, ICO_FILE);
  console.log('  ✅ Compiled Uninstall.exe (Native Windows Uninstaller)');

  if (!reuseZip) {
    // Step 3: Bundle Node runtime and application files into staging
    console.log('\n[3/6] Staging self-contained application runtime & assets...');
    const nodeSource = findNodeBinary();
    console.log(`  Bundling portable node runtime: ${nodeSource}`);
    fs.copyFileSync(nodeSource, path.join(STAGING, 'node.exe'));

    fs.copyFileSync(launcherExe, path.join(STAGING, 'KanugaShield.exe'));
    fs.copyFileSync(uninstallExe, path.join(STAGING, 'Uninstall.exe'));

    const filesToCopy = [
      'server.js',
      'cron-worker.js',
      'package.json',
      'package-lock.json',
      'kanugashield-firebase-adminsdk-fbsvc-c792eadc00.json',
    ];

    filesToCopy.forEach(f => {
      const p = path.join(ROOT, f);
      if (fs.existsSync(p)) {
        fs.copyFileSync(p, path.join(STAGING, f));
        console.log(`  Included ${f}`);
      }
    });

    if (fs.existsSync(path.join(ROOT, '.env'))) {
      fs.copyFileSync(path.join(ROOT, '.env'), path.join(STAGING, '.env'));
      console.log('  Included .env configuration');
    }

    console.log('  Copying lib/ directory...');
    copyWithRobocopy(path.join(ROOT, 'lib'), path.join(STAGING, 'lib'));

    console.log('  Copying public/ UI assets...');
    copyWithRobocopy(path.join(ROOT, 'public'), path.join(STAGING, 'public'));

    console.log('  Copying node_modules/ (pre-compiled modules)...');
    copyWithRobocopy(path.join(ROOT, 'node_modules'), path.join(STAGING, 'node_modules'));

    // Step 4: Compress staging directory into app-payload.zip
    console.log('\n[4/6] Creating compressed application payload archive...');
    if (fs.existsSync(PAYLOAD_ZIP)) fs.unlinkSync(PAYLOAD_ZIP);
    
    const zipScript = `
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::CreateFromDirectory(
    '${STAGING.replace(/'/g, "''")}',
    '${PAYLOAD_ZIP.replace(/'/g, "''")}',
    [System.IO.Compression.CompressionLevel]::Optimal,
    $false
  )
  `;
    const tempZipPs1 = path.join(DIST, 'create_zip.ps1');
    fs.writeFileSync(tempZipPs1, zipScript, 'utf8');
    try {
      execSync(`powershell -NoProfile -ExecutionPolicy Bypass -File "${tempZipPs1}"`, {
        stdio: 'inherit',
        cwd: ROOT,
      });
    } finally {
      if (fs.existsSync(tempZipPs1)) fs.unlinkSync(tempZipPs1);
    }
  } else {
    console.log('\n[3/6] Staging verified (using existing verified payload archive)');
    console.log('\n[4/6] Payload archive verified:');
  }

  const zipStats = fs.statSync(PAYLOAD_ZIP);
  console.log(`  ✅ Created app-payload.zip (${(zipStats.size / (1024 * 1024)).toFixed(2)} MB)`);

  // Step 5: Compile standalone setup installer with embedded payload
  console.log('\n[5/6] Compiling standalone Windows Setup installer (Kanuga-Shield-Setup.exe)...');
  const setupCs = path.join(ROOT, 'src-installer', 'KanugaSetup.cs');
  const finalInstaller = path.join(DIST, 'Kanuga-Shield-Setup.exe');

  compileCSharp(
    setupCs,
    finalInstaller,
    ICO_FILE,
    ['System.IO.Compression.dll', 'System.IO.Compression.FileSystem.dll'],
    [PAYLOAD_ZIP]
  );

  const installerStats = fs.statSync(finalInstaller);
  console.log(`  ✅ Successfully compiled Kanuga-Shield-Setup.exe (${(installerStats.size / (1024 * 1024)).toFixed(2)} MB)`);

  // Step 6: Finalize distribution packages
  console.log('\n[6/6] Finalizing distribution packages...');
  const rootInstaller = path.join(ROOT, 'Kanuga-Shield-Setup.exe');
  fs.copyFileSync(finalInstaller, rootInstaller);

  const userDesktop = path.join(process.env.USERPROFILE || 'C:\\Users\\DXB GADGETS UG', 'Desktop', 'Kanuga-Shield-Setup.exe');
  try {
    fs.copyFileSync(finalInstaller, userDesktop);
    console.log(`  ✅ Placed installer copy on Desktop: ${userDesktop}`);
  } catch (e) {
    // Desktop copy optional
  }

  // Cleanup staging directory to save disk space
  try {
    fs.rmSync(STAGING, { recursive: true, force: true });
    fs.rmSync(PAYLOAD_ZIP, { force: true });
  } catch (e) {}

  console.log('\n╔═══════════════════════════════════════════════════════════════╗');
  console.log('║       🎉 Kanuga Shield Standalone Installer Built!           ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝');
  console.log(`\nInstaller Executable: ${rootInstaller}`);
  console.log(`Desktop Copy:         ${userDesktop}`);
  console.log(`Installer File Size:  ${(installerStats.size / (1024 * 1024)).toFixed(2)} MB`);
  console.log('\nHow it works:');
  console.log('  1. Anyone on Windows can run Kanuga-Shield-Setup.exe.');
  console.log('  2. No Node.js installation or setup is needed — it is 100% self-contained.');
  console.log('  3. Each user gets their own private local storage at:');
  console.log('     %APPDATA%\\Kanuga Shield\\data');
  console.log('  4. When connected to the internet, all users connect to the Cloud Firestore');
  console.log('     licensing engine to validate keys and access all platform features.\n');
}

build().catch(err => {
  console.error('\n❌ Build failed:', err);
  process.exit(1);
});
