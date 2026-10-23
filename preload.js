const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('lockApi', {
  unlock: (code) => ipcRenderer.invoke('unlock', code),
  quit: () => ipcRenderer.send('quit-app')
});
