const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('api', {
  lockState: () => ipcRenderer.invoke('lock:state'),
  unlock: (pw) => ipcRenderer.invoke('lock:unlock', pw),
  setup: (pw) => ipcRenderer.invoke('lock:setup', pw),
  getSettings: () => ipcRenderer.invoke('settings:get'),
  saveSettings: (s) => ipcRenderer.invoke('settings:save', s),
  closeSettings: () => ipcRenderer.invoke('settings:close'),
});
