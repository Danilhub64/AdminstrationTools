import os
import subprocess
import psutil
import tkinter as tk
from tkinter import ttk, messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import platform

class MainForm(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Admin Resources")
        self.geometry("800x600")

        self.tabControl = ttk.Notebook(self)
        self.tabWindows = ttk.Frame(self.tabControl)
        self.tabLinux = ttk.Frame(self.tabControl)
        self.tabMac = ttk.Frame(self.tabControl)
        self.tabRecentChanges = ttk.Frame(self.tabControl)
        self.tabProcesses = ttk.Frame(self.tabControl)

        self.tabControl.add(self.tabWindows, text='Windows')
        self.tabControl.add(self.tabLinux, text='Linux')
        self.tabControl.add(self.tabMac, text='Mac')
        self.tabControl.add(self.tabRecentChanges, text='Recent Changes')
        self.tabControl.add(self.tabProcesses, text='Processes')

        self.tabControl.pack(expand=1, fill="both")

        if platform.system() == 'Windows':
            self.init_windows_tab()
        elif platform.system() == 'Linux':
            self.init_linux_tab()
        elif platform.system() == 'Darwin':  # MacOS
            self.init_mac_tab()
        
        self.init_recent_changes_tab()
        self.init_processes_tab()
        self.init_file_system_watcher()

    def init_windows_tab(self):
        self.btnDefenderScan = tk.Button(self.tabWindows, text="Run Defender Scan", command=self.run_defender_scan)
        self.btnDefenderScan.pack(side=tk.TOP, fill=tk.X)

        self.btnRemoveThreats = tk.Button(self.tabWindows, text="Remove Detected Threats", command=self.remove_detected_threats)
        self.btnRemoveThreats.pack(side=tk.TOP, fill=tk.X)

        admin_tools = [
            ("Computer Management", "compmgmt.msc"),
            ("Event Viewer", "eventvwr.msc"),
            ("Device Manager", "devmgmt.msc"),
            ("Disk Management", "diskmgmt.msc"),
            ("Task Scheduler", "taskschd.msc"),
            ("Performance Monitor", "perfmon.msc"),
            ("Local Security Policy", "secpol.msc"),
            ("Group Policy Editor", "gpedit.msc"),
            ("Registry Editor", "regedit.exe"),
            ("Services", "services.msc"),
            ("Windows Firewall", "firewall.cpl"),
        ]

        for tool_name, tool_command in admin_tools:
            btn = tk.Button(self.tabWindows, text=tool_name, command=lambda cmd=tool_command: self.run_as_admin(cmd))
            btn.pack(side=tk.TOP, fill=tk.X)

    def init_linux_tab(self):
        admin_tools = [
            ("System Monitor", "gnome-system-monitor"),
            ("Disk Usage Analyzer", "baobab"),
            ("Logs", "gnome-logs"),
            ("Software Updater", "update-manager"),
            ("Terminal", "gnome-terminal"),
            ("Users and Groups", "gnome-control-center user-accounts"),
            ("Network Manager", "nm-connection-editor"),
            ("Disk Utility", "gnome-disks"),
        ]

        for tool_name, tool_command in admin_tools:
            btn = tk.Button(self.tabLinux, text=tool_name, command=lambda cmd=tool_command: self.run_command(cmd))
            btn.pack(side=tk.TOP, fill=tk.X)

    def init_mac_tab(self):
        admin_tools = [
            ("Activity Monitor", "open -a 'Activity Monitor'"),
            ("Console", "open -a 'Console'"),
            ("Disk Utility", "open -a 'Disk Utility'"),
            ("Terminal", "open -a 'Terminal'"),
            ("System Preferences", "open -a 'System Preferences'"),
        ]

        for tool_name, tool_command in admin_tools:
            btn = tk.Button(self.tabMac, text=tool_name, command=lambda cmd=tool_command: self.run_command(cmd))
            btn.pack(side=tk.TOP, fill=tk.X)

    def init_recent_changes_tab(self):
        self.txtRecentChanges = tk.Text(self.tabRecentChanges)
        self.txtRecentChanges.pack(expand=1, fill=tk.BOTH)

    def init_processes_tab(self):
        self.listViewProcesses = ttk.Treeview(self.tabProcesses, columns=("PID", "Process Name", "Memory Usage"), show='headings')
        self.listViewProcesses.heading("PID", text="PID")
        self.listViewProcesses.heading("Process Name", text="Process Name")
        self.listViewProcesses.heading("Memory Usage", text="Memory Usage")

        self.listViewProcesses.pack(expand=1, fill=tk.BOTH)

        self.btnRefreshProcesses = tk.Button(self.tabProcesses, text="Refresh Processes", command=self.refresh_process_list)
        self.btnRefreshProcesses.pack(side=tk.TOP, fill=tk.X)

        self.txtProcessID = tk.Entry(self.tabProcesses)
        self.txtProcessID.pack(side=tk.TOP, fill=tk.X)
        self.txtProcessID.insert(0, "Enter Process ID")

        self.btnKillProcess = tk.Button(self.tabProcesses, text="Kill Process", command=self.kill_process)
        self.btnKillProcess.pack(side=tk.TOP, fill=tk.X)

    def run_defender_scan(self):
        try:
            output = subprocess.check_output(["powershell.exe", "-Command", "Start-MpScan -ScanType FullScan"])
            messagebox.showinfo("Defender Scan Output", output.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Error starting scan: {e}")

    def remove_detected_threats(self):
        try:
            output = subprocess.check_output(["powershell.exe", "-Command", "Remove-MpThreatDetection"])
            messagebox.showinfo("Defender Removal Output", output.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Error removing threats: {e}")

    def run_as_admin(self, command):
        try:
            subprocess.run(["powershell.exe", "Start-Process", command, "-Verb", "runAs"])
        except Exception as e:
            messagebox.showerror("Error", f"Error running {command}: {e}")

    def run_command(self, command):
        try:
            subprocess.run(command, shell=True)
        except Exception as e:
            messagebox.showerror("Error", f"Error running {command}: {e}")

    def init_file_system_watcher(self):
        self.event_handler = MyFileSystemEventHandler(self.txtRecentChanges)
        self.observer = Observer()
        self.observer.schedule(self.event_handler, path='C:\\' if platform.system() == 'Windows' else '/', recursive=True)
        self.observer.start()

    def refresh_process_list(self):
        for i in self.listViewProcesses.get_children():
            self.listViewProcesses.delete(i)

        for process in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                pid = process.info['pid']
                name = process.info['name']
                memory = process.info['memory_info'].rss // 1024
                self.listViewProcesses.insert("", "end", values=(pid, name, f"{memory} KB"))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def kill_process(self):
        try:
            pid = int(self.txtProcessID.get())
            process = psutil.Process(pid)
            process.terminate()
            process.wait()
            messagebox.showinfo("Info", "Process terminated successfully.")
            self.refresh_process_list()
        except Exception as e:
            messagebox.showerror("Error", f"Error terminating process: {e}")

class MyFileSystemEventHandler(FileSystemEventHandler):
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def on_modified(self, event):
        self.text_widget.insert(tk.END, f"Modified: {event.src_path}\n")
        self.text_widget.see(tk.END)

    def on_created(self, event):
        self.text_widget.insert(tk.END, f"Created: {event.src_path}\n")
        self.text_widget.see(tk.END)

    def on_deleted(self, event):
        self.text_widget.insert(tk.END, f"Deleted: {event.src_path}\n")
        self.text_widget.see(tk.END)

    def on_moved(self, event):
        self.text_widget.insert(tk.END, f"Renamed: {event.src_path} to {event.dest_path}\n")
        self.text_widget.see(tk.END)

if __name__ == "__main__":
    app = MainForm()
    app.mainloop()



