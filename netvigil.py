#!/usr/bin/env python3
"""
NetVigil - Network Monitor with Grouping & Game Filtering
Modern Dark UI, 3 Tabs, Custom Dark Title Bar
"""

import sys
import socket
import ipaddress
import threading
import os
from datetime import datetime
from collections import defaultdict

import psutil
import requests
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QTreeWidgetItemIterator,
    QHeaderView, QLabel, QPushButton, QFrame, QMessageBox,
    QTabWidget, QListWidget, QLineEdit, QAbstractItemView, QSizeGrip
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QPoint
from PyQt5.QtGui import QColor, QBrush, QFont

# ----------------------------------------------------------------------
# Filter file handling
# ----------------------------------------------------------------------
FILTER_FILE = "game_filters.txt"

DEFAULT_FILTERS = {
    "steam.exe", "steamwebhelper.exe", "steamservice.exe",
    "rockstar.exe", "socialclub.exe", "launcher.exe",
    "epicgameslauncher.exe", "origin.exe", "originwebhelper.exe",
    "uplay.exe", "upc.exe", "ubisoftconnect.exe",
    "battle.net.exe", "battlenet.exe",
    "riotclientservices.exe", "league of legends.exe", "valorant.exe",
    "goggalaxy.exe", "bethesda.net launcher.exe",
    "gamelauncher.exe", "gamingservices.exe",
    "xbox.exe", "xboxgamebar.exe",
    "overwatch.exe", "cod.exe", "csgo.exe",
    "fifa.exe", "nba2k.exe", "gta5.exe", "rdr2.exe",
    "fortnite.exe", "minecraft.exe", "roblox.exe"
}

def load_filters():
    if not os.path.exists(FILTER_FILE):
        save_filters(DEFAULT_FILTERS)
        return DEFAULT_FILTERS.copy()
    with open(FILTER_FILE, "r", encoding="utf-8") as f:
        lines = [line.strip().lower() for line in f if line.strip()]
    return set(lines)

def save_filters(filters):
    with open(FILTER_FILE, "w", encoding="utf-8") as f:
        for name in sorted(filters):
            f.write(name + "\n")

# ----------------------------------------------------------------------
# Country Resolver
# ----------------------------------------------------------------------
class CountryResolver:
    _cache = {}
    _pending = set()
    _lock = threading.Lock()

    _services = [
        {
            "url": "http://ip-api.com/json/{}?fields=country",
            "parser": lambda resp: resp.json().get("country", "Unknown"),
            "timeout": 3
        },
        {
            "url": "https://ipwho.is/{}",
            "parser": lambda resp: resp.json().get("country", "Unknown"),
            "timeout": 4
        },
        {
            "url": "https://freeipapi.com/api/json/{}",
            "parser": lambda resp: resp.json().get("countryName", "Unknown"),
            "timeout": 4
        }
    ]
    _headers = {"User-Agent": "NetVigil/1.0"}

    @classmethod
    def get_country(cls, ip: str, callback=None):
        with cls._lock:
            if ip in cls._cache:
                return cls._cache[ip]
            if ip in cls._pending:
                return "🔄"
        cls._pending.add(ip)
        threading.Thread(target=cls._fetch, args=(ip, callback), daemon=True).start()
        return "..."

    @classmethod
    def _fetch(cls, ip: str, callback=None):
        country = "Unknown"
        for service in cls._services:
            try:
                url = service["url"].format(ip)
                resp = requests.get(url, timeout=service["timeout"], headers=cls._headers)
                if resp.status_code == 200:
                    c = service["parser"](resp)
                    if c and isinstance(c, str) and c != "Unknown":
                        country = c
                        break
            except Exception:
                continue
        with cls._lock:
            cls._cache[ip] = country
            cls._pending.discard(ip)
        if callback:
            callback(ip, country)

# ----------------------------------------------------------------------
# Background Scanner
# ----------------------------------------------------------------------
class NetworkScanner(QThread):
    data_ready = pyqtSignal(dict)
    speed_ready = pyqtSignal(float, float)

    def __init__(self):
        super().__init__()
        self.running = True
        self.prev_net = psutil.net_io_counters()
        self.prev_time = datetime.now()

    def run(self):
        while self.running:
            self._scan_connections()
            self._update_speed()
            self.msleep(2000)

    def _scan_connections(self):
        groups = defaultdict(lambda: {'pids': set(), 'connections': []})
        try:
            for conn in psutil.net_connections(kind='inet'):
                if not conn.raddr or len(conn.raddr) < 2:
                    continue
                remote_ip, remote_port = conn.raddr
                if self._is_private(remote_ip) or remote_port == 0:
                    continue
                pid = conn.pid if conn.pid else 0
                proc_name = self._get_process_name(pid)
                if not proc_name:
                    proc_name = "System" if pid == 0 else f"PID:{pid}"
                local_ip = conn.laddr[0] if conn.laddr else "0.0.0.0"
                local_port = conn.laddr[1] if conn.laddr else 0
                proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                status = conn.status if conn.status else "-"
                groups[proc_name]['pids'].add(pid)
                groups[proc_name]['connections'].append({
                    'pid': pid,
                    'local': f"{local_ip}:{local_port}",
                    'remote': f"{remote_ip}:{remote_port}",
                    'proto': proto,
                    'status': status,
                    'remote_ip': remote_ip
                })
        except Exception as e:
            print(f"Scan error: {e}")
        self.data_ready.emit(groups)

    def _update_speed(self):
        try:
            cur = psutil.net_io_counters()
            now = datetime.now()
            dt = (now - self.prev_time).total_seconds()
            if dt > 0:
                down = (cur.bytes_recv - self.prev_net.bytes_recv) / dt
                up = (cur.bytes_sent - self.prev_net.bytes_sent) / dt
                self.speed_ready.emit(down, up)
            self.prev_net, self.prev_time = cur, now
        except:
            pass

    def _is_private(self, ip: str) -> bool:
        try:
            if ':' in ip:
                return ip.startswith(('fe80', '::1')) or ip == '::'
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast
        except:
            return True

    def _get_process_name(self, pid: int) -> str:
        try:
            return psutil.Process(pid).name()
        except:
            return None

    def stop(self):
        self.running = False
        self.quit()
        self.wait()

# ----------------------------------------------------------------------
# Main Window
# ----------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        # Frameless window with custom title bar
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, False)

        self.setWindowTitle("NetVigil - Network Monitor")
        self.setGeometry(100, 100, 1300, 750)
        self.setMinimumSize(1050, 600)

        self.dragging = False
        self.drag_position = QPoint()

        self.game_filters = load_filters()
        self.last_groups = {}

        self.scanner = NetworkScanner()
        self.scanner.data_ready.connect(self.receive_data)
        self.scanner.speed_ready.connect(self.update_speed)
        self.scanner.start()

        self.setup_ui()

        self.country_timer = QTimer()
        self.country_timer.timeout.connect(self.refresh_countries_in_tree)
        self.country_timer.start(1000)

        self.expanded_items = set()
        self.tabs.currentChanged.connect(self.on_tab_changed)

    def setup_ui(self):
        # Global dark style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0d1117;
            }
            QLabel {
                color: #c9d1d9;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
            }
            QTreeWidget {
                background-color: #161b22;
                alternate-background-color: #1c2129;
                gridline-color: #30363d;
                font-family: 'Segoe UI', 'Consolas';
                font-size: 11px;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                selection-background-color: #1f6feb;
            }
            QTreeWidget::item {
                padding: 4px;
            }
            QTreeWidget::item:selected {
                background-color: #1f6feb;
                color: white;
            }
            QHeaderView::section {
                background-color: #21262d;
                color: #c9d1d9;
                font-weight: bold;
                padding: 6px;
                border: none;
                border-bottom: 1px solid #30363d;
            }
            QPushButton {
                background-color: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px 12px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #30363d;
                border-color: #8b949e;
            }
            QPushButton:pressed {
                background-color: #1f6feb;
                color: white;
            }
            QFrame#headerFrame {
                background-color: #161b22;
                border-radius: 8px;
                border: 1px solid #30363d;
            }
            QTabWidget::pane {
                border: none;
                background-color: #0d1117;
            }
            QTabBar::tab {
                background-color: #21262d;
                color: #8b949e;
                border: 1px solid #30363d;
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                padding: 8px 20px;
                margin-right: 4px;
                font-weight: bold;
                font-size: 12px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #58a6ff;
                border-bottom: 2px solid #58a6ff;
            }
            QTabBar::tab:hover {
                background-color: #30363d;
            }
            QListWidget {
                background-color: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                font-size: 12px;
            }
            QLineEdit {
                background-color: #0d1117;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 6px;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #58a6ff;
            }
            /* Window control buttons */
            QPushButton#btnMin, QPushButton#btnMax, QPushButton#btnClose {
                border: none;
                background-color: transparent;
                font-size: 16px;
                padding: 0px 10px;
                color: #c9d1d9;
            }
            QPushButton#btnMin:hover, QPushButton#btnMax:hover {
                background-color: #30363d;
            }
            QPushButton#btnClose:hover {
                background-color: #da3633;
                color: white;
            }
        """)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(0, 0, 0, 0)  # remove margins for frameless look

        # ---- Custom Title Bar (Header) ----
        header = QFrame(objectName="headerFrame")
        header.setFixedHeight(40)
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(10, 0, 5, 0)
        h_layout.setSpacing(10)

        # Title text
        title_lbl = QLabel("⚡ NETVIGIL")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #58a6ff; background: transparent; border: none;")
        h_layout.addWidget(title_lbl)
        h_layout.addStretch()

        # Speed cards (compact)
        self.down_card = self._create_card("📥", "0 KB/s", "#3fb950", compact=True)
        self.up_card = self._create_card("📤", "0 KB/s", "#d2991d", compact=True)
        h_layout.addWidget(self.down_card)
        h_layout.addWidget(self.up_card)

        h_layout.addStretch()

        # Window control buttons
        btn_min = QPushButton("─")
        btn_min.setObjectName("btnMin")
        btn_min.clicked.connect(self.showMinimized)
        h_layout.addWidget(btn_min)

        self.btn_max = QPushButton("□")
        self.btn_max.setObjectName("btnMax")
        self.btn_max.clicked.connect(self.toggle_maximize)
        h_layout.addWidget(self.btn_max)

        btn_close = QPushButton("✕")
        btn_close.setObjectName("btnClose")
        btn_close.clicked.connect(self.close)
        h_layout.addWidget(btn_close)

        self.header = header  # save reference for drag detection
        main_layout.addWidget(header)

        # ---- Tabs ----
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Tab 1: All Connections
        self.tab_all = QWidget()
        all_layout = QVBoxLayout(self.tab_all)
        all_layout.setContentsMargins(10, 4, 10, 0)
        self.tree_all = self._create_tree()
        all_layout.addWidget(self.tree_all)
        self.tabs.addTab(self.tab_all, "🌐 All Connections")

        # Tab 2: Games & Launchers
        self.tab_games = QWidget()
        games_layout = QVBoxLayout(self.tab_games)
        games_layout.setContentsMargins(10, 4, 10, 0)
        self.tree_games = self._create_tree()
        games_layout.addWidget(self.tree_games)
        self.tabs.addTab(self.tab_games, "🎮 Games & Launchers")

        # Tab 3: Manage Filters
        self.tab_filters = QWidget()
        filter_layout = QVBoxLayout(self.tab_filters)
        filter_layout.setContentsMargins(10, 4, 10, 0)

        lbl = QLabel("📋 Process names to show in Games & Launchers tab:")
        lbl.setStyleSheet("font-weight: bold; font-size: 13px;")
        filter_layout.addWidget(lbl)

        self.filter_list = QListWidget()
        self.filter_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.filter_list.addItems(sorted(self.game_filters))
        filter_layout.addWidget(self.filter_list)

        row = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g. mygame.exe")
        self.filter_input.returnPressed.connect(self.add_filter)
        row.addWidget(self.filter_input)

        add_btn = QPushButton("➕ Add")
        add_btn.clicked.connect(self.add_filter)
        row.addWidget(add_btn)

        del_btn = QPushButton("🗑️ Remove Selected")
        del_btn.clicked.connect(self.remove_filter)
        row.addWidget(del_btn)
        filter_layout.addLayout(row)
        self.tabs.addTab(self.tab_filters, "⚙️ Manage Filters")

        # ---- Bottom status bar with size grip ----
        status_frame = QFrame()
        status_frame.setStyleSheet("QFrame { background-color: #161b22; border-radius: 0px; }")
        s_layout = QHBoxLayout(status_frame)
        s_layout.setContentsMargins(10, 4, 10, 4)
        self.status_label = QLabel("🟢 Monitoring active connections...")
        s_layout.addWidget(self.status_label)
        s_layout.addStretch()
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(lambda: self.scanner._scan_connections())
        s_layout.addWidget(refresh_btn)

        # Size grip for resizing
        size_grip = QSizeGrip(self)
        s_layout.addWidget(size_grip, 0, Qt.AlignBottom | Qt.AlignRight)

        main_layout.addWidget(status_frame)

    def _create_card(self, title, value, color, compact=False):
        card = QFrame()
        if compact:
            card.setFixedSize(100, 32)
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: #21262d;
                    border: 1px solid {color};
                    border-radius: 6px;
                }}
            """)
            layout = QHBoxLayout(card)
            layout.setContentsMargins(8, 2, 8, 2)
            layout.setSpacing(4)
            t = QLabel(title)
            t.setStyleSheet(f"color: {color}; font-size: 10px; font-weight: bold; background: transparent; border: none;")
            v = QLabel(value)
            v.setStyleSheet("color: white; font-size: 12px; font-weight: bold; background: transparent; border: none;")
            layout.addWidget(t)
            layout.addWidget(v)
            if title == "📥":
                self.down_val = v
            else:
                self.up_val = v
        else:
            card.setFixedSize(145, 60)
            card.setStyleSheet(f"""
                QFrame {{
                    background-color: #21262d;
                    border: 1px solid {color};
                    border-radius: 8px;
                }}
            """)
            layout = QVBoxLayout(card)
            layout.setContentsMargins(10, 6, 10, 6)
            t = QLabel(title)
            t.setStyleSheet(f"color: {color}; font-size: 10px; font-weight: bold;")
            v = QLabel(value)
            v.setStyleSheet("color: white; font-size: 15px; font-weight: bold;")
            layout.addWidget(t)
            layout.addWidget(v)
            if title == "📥 DOWNLOAD":
                self.down_val = v
            else:
                self.up_val = v
        return card

    def _create_tree(self):
        tree = QTreeWidget()
        tree.setHeaderLabels(["Process", "PID", "Local", "Remote", "Country", "Protocol", "Status"])
        tree.setIndentation(20)
        tree.setAlternatingRowColors(True)
        tree.setSortingEnabled(True)
        header = tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)
        return tree

    # ---------- Drag window by title bar ----------
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            # Check if click is on the header bar
            if self.header.underMouse():
                self.dragging = True
                self.drag_position = event.globalPos() - self.frameGeometry().topLeft()
                event.accept()
            else:
                self.dragging = False
        else:
            self.dragging = False

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and self.dragging:
            self.move(event.globalPos() - self.drag_position)
            event.accept()

    def mouseReleaseEvent(self, event):
        self.dragging = False

    # ---------- Maximize / Restore ----------
    def toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
            self.btn_max.setText("□")
        else:
            self.showMaximized()
            self.btn_max.setText("❐")

    # ---------- Data handling ----------
    def receive_data(self, groups):
        self.last_groups = groups
        self.refresh_active_tree()

    def on_tab_changed(self, index):
        self.refresh_active_tree()

    def refresh_active_tree(self):
        current_tab = self.tabs.currentIndex()
        if current_tab == 2:  # Filters tab
            return

        tree = self.tree_all if current_tab == 0 else self.tree_games
        apply_filter = (current_tab == 1)

        self._save_expanded_state(tree)
        tree.clear()
        if not self.last_groups:
            self.status_label.setText("🟢 No connections detected.")
            return

        total_conns = 0
        for proc_name, data in self.last_groups.items():
            if apply_filter and proc_name.lower() not in self.game_filters:
                continue
            pids = data['pids']
            conns = data['connections']
            total_conns += len(conns)
            parent = QTreeWidgetItem(tree)
            parent.setText(0, f"📦 {proc_name}")
            parent.setText(1, f"{len(pids)} PID(s)")
            parent.setData(0, Qt.UserRole, f"proc_{proc_name}")
            if f"proc_{proc_name}" in self.expanded_items:
                parent.setExpanded(True)

            pid_to_conns = defaultdict(list)
            for c in conns:
                pid_to_conns[c['pid']].append(c)

            for pid, pid_conns in pid_to_conns.items():
                pid_item = QTreeWidgetItem(parent)
                try:
                    pid_name = psutil.Process(pid).name() if pid != 0 else "System"
                except:
                    pid_name = "Unknown"
                pid_item.setText(0, f"  ├─ PID {pid} ({pid_name})")
                pid_item.setText(1, str(pid))
                pid_item.setForeground(1, QBrush(QColor(150, 150, 150)))
                pid_item.setData(0, Qt.UserRole, f"pid_{proc_name}_{pid}")
                if f"pid_{proc_name}_{pid}" in self.expanded_items:
                    pid_item.setExpanded(True)

                for conn in pid_conns:
                    remote_ip = conn['remote_ip']
                    country = CountryResolver.get_country(remote_ip, self._on_country_ready)
                    child = QTreeWidgetItem(pid_item)
                    child.setText(0, "     └─ Connection")
                    child.setText(1, "")
                    child.setText(2, conn['local'])
                    child.setText(3, conn['remote'])
                    child.setText(4, country)
                    child.setText(5, conn['proto'])
                    child.setText(6, conn['status'])
                    child.setData(0, Qt.UserRole, remote_ip)

        self.status_label.setText(f"🟢 {total_conns} connections | {len(self.last_groups)} processes")

    def _save_expanded_state(self, tree):
        self.expanded_items.clear()
        iterator = QTreeWidgetItemIterator(tree)
        while iterator.value():
            item = iterator.value()
            if item.isExpanded():
                uid = item.data(0, Qt.UserRole)
                if uid:
                    self.expanded_items.add(uid)
            iterator += 1

    def _on_country_ready(self, ip, country):
        self.refresh_countries_in_tree()

    def refresh_countries_in_tree(self):
        for tree in [self.tree_all, self.tree_games]:
            iterator = QTreeWidgetItemIterator(tree)
            while iterator.value():
                item = iterator.value()
                if item.parent() and item.parent().parent():
                    ip = item.data(0, Qt.UserRole)
                    if ip and isinstance(ip, str) and '.' in ip:
                        country = CountryResolver.get_country(ip)
                        if country and country not in ("...", "🔄"):
                            item.setText(4, country)
                iterator += 1

    def update_speed(self, down_bps, up_bps):
        self.down_val.setText(self._format_speed(down_bps))
        self.up_val.setText(self._format_speed(up_bps))

    def _format_speed(self, bps):
        if bps < 1024:
            return f"{bps:.0f} B/s"
        elif bps < 1024*1024:
            return f"{bps/1024:.1f} KB/s"
        else:
            return f"{bps/(1024*1024):.1f} MB/s"

    # ---- Filter management ----
    def add_filter(self):
        name = self.filter_input.text().strip().lower()
        if not name:
            return
        self.game_filters.add(name)
        save_filters(self.game_filters)
        self.filter_list.clear()
        self.filter_list.addItems(sorted(self.game_filters))
        self.filter_input.clear()
        self.refresh_active_tree()

    def remove_filter(self):
        selected = self.filter_list.selectedItems()
        if not selected:
            return
        for item in selected:
            self.game_filters.discard(item.text().lower())
        save_filters(self.game_filters)
        self.filter_list.clear()
        self.filter_list.addItems(sorted(self.game_filters))
        self.refresh_active_tree()

    def closeEvent(self, event):
        self.scanner.stop()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    try:
        psutil.net_connections()
    except:
        QMessageBox.warning(None, "Limited Access", "Run as Administrator to see all connections.")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())