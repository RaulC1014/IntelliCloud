import { app, BrowserWindow } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawn } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mainWindow;
let pythonBackendProcess;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  const isDev = process.env.VITE_DEV_SERVER_URL;

  if (isDev) {
    mainWindow.loadURL(isDev);
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
    mainWindow.webContents.openDevTools();
  }
}

app.whenReady().then(() => {
    const isDev = process.env.VITE_DEV_SERVER_URL;
  
    if (isDev) {
      // DEVELOPMENT MODE (Uses your .venv)
      const backendDir = path.join(__dirname, '../../intellicloud-backend');
      const pythonExe = path.join(backendDir, '.venv/bin/python');
      
      console.log('Starting DEV Python Backend from:', pythonExe);
      pythonBackendProcess = spawn(pythonExe, ['app.py'], { cwd: backendDir });
  
    } else {
      // PRODUCTION MODE (Uses the PyInstaller compiled executable)
      // process.resourcesPath is the special folder inside the built Mac .app where we will stash the backend
      const exeName = process.platform === 'win32' ? 'intellicloud-api.exe' : 'intellicloud-api';
      const executablePath = path.join(process.resourcesPath, 'backend-api', exeName);
      
      console.log('Starting PROD Python Backend from:', executablePath);
      
      // We set the cwd (Current Working Directory) to the backend-api folder so it can find rules.yaml
      const backendDir = path.join(process.resourcesPath, 'backend-api');
      pythonBackendProcess = spawn(executablePath, [], { cwd: backendDir });
    }
  
    // Print logs for both Dev and Prod
    pythonBackendProcess.stdout.on('data', (data) => {
      console.log(`[BACKEND]: ${data.toString().trim()}`);
    });
  
    pythonBackendProcess.stderr.on('data', (data) => {
      console.log(`[BACKEND LOG]: ${data.toString().trim()}`);
    });
  
    createWindow();
  
    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

// VERY IMPORTANT: This kills the Python backend when you close the Electron window
app.on('will-quit', () => {
  if (pythonBackendProcess) {
    console.log('Shutting down Python Backend...');
    pythonBackendProcess.kill();
  }
});

app.on('window-all-closed', () => {
    app.quit();
  });