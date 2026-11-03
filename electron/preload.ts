import { contextBridge, ipcRenderer, webUtils } from 'electron'

contextBridge.exposeInMainWorld('sentinelGuard', {
  getFilePath: (file: File) => {
    try {
      return webUtils.getPathForFile(file)
    } catch {
      return ''
    }
  },
  getStatus: () => ipcRenderer.invoke('guard:get-status'),
  setConfig: (config: { enabled?: boolean; autoQuarantine?: boolean; canaryEnabled?: boolean }) =>
    ipcRenderer.invoke('guard:set-config', config),
  scanDirectory: () => ipcRenderer.invoke('guard:scan-directory'),
  startQuickScan: () => ipcRenderer.invoke('guard:quick-scan'),
  stopScan: () => ipcRenderer.invoke('guard:stop-scan'),
  quarantineFile: (filePath: string, reason?: string) =>
    ipcRenderer.invoke('guard:quarantine-file', filePath, reason),
  restoreQuarantine: (id: string) => ipcRenderer.invoke('guard:restore-quarantine', id),
  deleteQuarantine: (id: string) => ipcRenderer.invoke('guard:delete-quarantine', id),
  listProcesses: () => ipcRenderer.invoke('guard:list-processes'),
  killProcess: (pid: number, quarantineExe?: boolean) =>
    ipcRenderer.invoke('guard:kill-process', pid, quarantineExe),
  clearAlerts: () => ipcRenderer.invoke('guard:clear-alerts'),
  onStatusUpdate: (callback: (status: unknown) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, status: unknown) => callback(status)
    ipcRenderer.on('guard:status-updated', listener)
    return () => {
      ipcRenderer.removeListener('guard:status-updated', listener)
    }
  },
})
