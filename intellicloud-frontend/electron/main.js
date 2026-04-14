// @ts-nocheck
/* eslint-disable */

const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;
let pythonBackendProcess;

// We use the variable passed from our package.json script
const isDev = process.env.NODE_ENV === 'development';

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  if (isDev) {
    // In development, wait-on guarantees Vite is running here
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools();
  } else {
    // In production, load the bundled React app
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }
}

app.whenReady().then(() => {
    if (isDev) {
      // --- DEVELOPMENT MODE ---
      // We look for the intellicloud-backend folder next to intellicloud-frontend
      const backendDir = path.join(__dirname, '../../intellicloud-backend');
      
      // Determine if we are on Windows or Mac/Linux for the python executable
      const isWindows = process.platform === 'win32';
      const pythonExe = isWindows 
        ? path.join(backendDir, '.venv/Scripts/python.exe')
        : path.join(backendDir, '.venv/bin/python');
      
      console.log('Starting DEV Python Backend from:', pythonExe);
      pythonBackendProcess = spawn(pythonExe, ['app.py'], { cwd: backendDir });

    } else {
      // --- PRODUCTION MODE ---
      const exeName = process.platform === 'win32' ? 'intellicloud-api.exe' : 'intellicloud-api';
      const backendDir = path.join(process.resourcesPath, 'backend-api');
      const executablePath = path.join(backendDir, exeName);
      
      console.log('Starting PROD Python Backend from:', executablePath);
      pythonBackendProcess = spawn(executablePath, [], { cwd: backendDir });
    }

    // Capture logs so we can see Python errors in the Electron terminal
    if (pythonBackendProcess) {
        pythonBackendProcess.stdout.on('data', (data) => {
          console.log(`[BACKEND]: ${data.toString().trim()}`);
        });

        pythonBackendProcess.stderr.on('data', (data) => {
          console.error(`[BACKEND ERR]: ${data.toString().trim()}`);
        });
    }

    createWindow();
  
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

// VERY IMPORTANT: Clean up the Python process when Electron closes
app.on('will-quit', () => {
  if (pythonBackendProcess) {
    console.log('Shutting down Python Backend...');
    pythonBackendProcess.kill();
  }
});

app.on('window-all-closed', () => {
  app.quit();
});