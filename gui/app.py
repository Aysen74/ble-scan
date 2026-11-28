"""
Главное окно приложения BLE Privacy Monitor.

Улучшения:
- Отображение MAC-адресов устройств
- Иконки производителей (Apple 🍎, Samsung 📺, Microsoft 🪟 и т.д.)
- Кликабельные профили с детальной информацией
- Объединение профилей по MAC-адресу
"""

import json
import threading
import time
from pathlib import Path
from tkinter import ttk
from storage import db, persist
import customtkinter as ctk

# Добавляем корень проекта в sys.path. ВАЖНО: вставляем в НАЧАЛО списка,
# причём безусловно (даже если путь уже где-то есть). Иначе при запуске вида
# `uv run --python 3.12 python gui/app.py` другие пути оказываются раньше,
# и локальные пакеты parser/profiles/engine/storage не находятся
# (ModuleNotFoundError: No module named 'parser').
import sys
ROOT = Path(__file__).resolve().parent.parent
_root_str = str(ROOT)
if _root_str in sys.path:
    sys.path.remove(_root_str)
sys.path.insert(0, _root_str)

from profiles.device_profile import DeviceProfiler, merge_profiles_by_mac
from engine.pipeline import evaluate
from engine.settings import load_config
from storage.alert_manager import AlertManager


# Словарь иконок производителей (emoji)
VENDOR_ICONS = {
    "0x004C": "🍎",      # Apple
    "0x0075": "📺",      # Samsung
    "0x0006": "🪟",      # Microsoft
    "0x0D23": "❄️",      # Gree (кондиционеры)
    "0x07D0": "🏠",      # Tuya (умный дом)
    "0x00E0": "🔍",      # Google
}

# Словарь названий производителей
VENDOR_NAMES = {
    "0x004C": "Apple",
    "0x0075": "Samsung",
    "0x0006": "Microsoft",
    "0x0D23": "Gree",
    "0x07D0": "Tuya",
    "0x00E0": "Google",
}


def normalize_company_id(cid: str) -> str:
    """Приводит company_id к формату 0x00XX."""
    cid = str(cid).upper()
    if cid.startswith("0X"):
        cid = cid[2:]
    return f"0x{cid.zfill(4)}"


def get_device_icon(decoded: dict) -> str:
    """Возвращает иконку производителя по manufacturer_data."""
    mfg = decoded.get("manufacturer_data", {})
    for cid in mfg:
        cid_norm = normalize_company_id(cid)
        if cid_norm in VENDOR_ICONS:
            return VENDOR_ICONS[cid_norm]
    return "📡"


def get_vendor_name(decoded: dict) -> str:
    """Возвращает название производителя."""
    mfg = decoded.get("manufacturer_data", {})
    for cid in mfg:
        cid_norm = normalize_company_id(cid)
        if cid_norm in VENDOR_NAMES:
            return VENDOR_NAMES[cid_norm]
    return "Unknown"


def device_label(decoded: dict) -> str:
    """Возвращает читаемое имя устройства."""
    name = decoded.get("local_name")
    if name:
        return str(name)
    return get_vendor_name(decoded)


class BLEMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("BLE Privacy Monitor")
        self.geometry("1400x900")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Состояние приложения
        self.is_collecting = False
        self.collector_thread = None
        self.profiler = DeviceProfiler(window=256)
        self.alert_manager = AlertManager(
            ROOT / "data" / "alerts" / "alerts.jsonl",
            load_config().get("alert_cooldown_sec", 60)
        )

        # Главный контейнер с вкладками
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)

        # Создаём вкладки
        self.tab_monitor = self.tabview.add("📡 Мониторинг")
        self.tab_alerts = self.tabview.add("⚠️ Алерты")
        self.tab_analysis = self.tabview.add("🔍 Анализ файла")

        # Инициализируем содержимое вкладок
        self._build_monitor_tab()
        self._build_alerts_tab()
        self._build_analysis_tab()

    # ------------------------------------------------------------------
    # Вкладка 1: Мониторинг
    # ------------------------------------------------------------------
    def _build_monitor_tab(self):
        # Кнопки управления
        btn_frame = ctk.CTkFrame(self.tab_monitor)
        btn_frame.pack(fill="x", padx=10, pady=10)

        self.btn_start = ctk.CTkButton(
            btn_frame, text="▶ Начать сбор", command=self._start_collection,
            fg_color="green", hover_color="darkgreen"
        )
        self.btn_start.pack(side="left", padx=5)

        self.btn_stop = ctk.CTkButton(
            btn_frame, text="⏹ Остановить", command=self._stop_collection,
            fg_color="red", hover_color="darkred", state="disabled"
        )
        self.btn_stop.pack(side="left", padx=5)

        self.btn_refresh = ctk.CTkButton(
            btn_frame, text="🔄 Обновить", command=self._update_device_list
        )
        self.btn_refresh.pack(side="left", padx=5)

        self.lbl_status = ctk.CTkLabel(btn_frame, text="Статус: неактивен")
        self.lbl_status.pack(side="right", padx=5)

        # Разделитель
        separator = ctk.CTkFrame(self.tab_monitor, height=2)
        separator.pack(fill="x", padx=10, pady=5)

        # Левая панель: список устройств
        list_frame = ctk.CTkFrame(self.tab_monitor)
        list_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(list_frame, text="Устройства", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=5)

        # Treeview для списка устройств
        columns = ("icon", "name", "mac", "packets", "rssi", "vendor")
        self.device_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=20)

        self.device_tree.heading("icon", text="")
        self.device_tree.heading("name", text="Имя")
        self.device_tree.heading("mac", text="MAC")
        self.device_tree.heading("packets", text="Пакетов")
        self.device_tree.heading("rssi", text="RSSI")
        self.device_tree.heading("vendor", text="Производитель")

        self.device_tree.column("icon", width=30, anchor="center")
        self.device_tree.column("name", width=150)
        self.device_tree.column("mac", width=130)
        self.device_tree.column("packets", width=70, anchor="center")
        self.device_tree.column("rssi", width=70, anchor="center")
        self.device_tree.column("vendor", width=100)

        # Стиль для Treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b")
        style.configure("Treeview.Heading", background="#1f538d", foreground="white")
        style.map("Treeview", background=[("selected", "#1f538d")])

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)

        self.device_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Обработчик клика
        self.device_tree.bind("<ButtonRelease-1>", self._on_device_select)

        # Правая панель: детали устройства
        detail_frame = ctk.CTkFrame(self.tab_monitor, width=400)
        detail_frame.pack(side="right", fill="y", padx=10, pady=10)
        detail_frame.pack_propagate(False)

        ctk.CTkLabel(detail_frame, text="Детали устройства", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)

        self.device_detail = ctk.CTkTextbox(detail_frame)
        self.device_detail.pack(fill="both", expand=True, padx=5, pady=5)
        self.device_detail.insert("1.0", "Выберите устройство из списка для просмотра деталей.\n")

    def _on_device_select(self, event):
        """Обработчик клика по устройству в списке."""
        selection = self.device_tree.selection()
        if not selection:
            return

        item = selection[0]
        values = self.device_tree.item(item, "values")
        if not values:
            return

        mac = values[2]  # MAC-адрес в колонке 3

        # Найти профиль по MAC
        profile = None
        for p in self.profiler.profiles.values():
            for mac_entry in p.mac_history:
                if mac_entry["mac"] == mac:
                    profile = p
                    break
            if profile:
                break

        if profile:
            self._show_device_details(profile)

    def _show_device_details(self, profile):
        """Показывает детальную информацию об устройстве."""
        self.device_detail.delete("1.0", "end")

        snap = profile.stable_snapshot or {}
        rssi_stats = profile.rssi_stats()
        interval_stats = profile.interval_stats()

        self.device_detail.insert("end", f"{'='*50}\n")
        self.device_detail.insert("end", f"Имя: {snap.get('local_name', 'N/A')}\n")
        self.device_detail.insert("end", f"MAC: {profile.mac_history[0]['mac'] if profile.mac_history else 'N/A'}\n")
        self.device_detail.insert("end", f"Производитель: {get_vendor_name(snap)}\n")
        self.device_detail.insert("end", f"{'='*50}\n\n")

        self.device_detail.insert("end", f"📦 СТАТИСТИКА\n")
        self.device_detail.insert("end", f"  Пакетов: {profile.packet_count}\n")
        self.device_detail.insert("end", f"  Уникальных MAC: {len(profile.mac_history)}\n")
        self.device_detail.insert("end", f"  Дубликатов отброшено: {profile.duplicate_count}\n\n")

        self.device_detail.insert("end", f"📶 RSSI\n")
        if rssi_stats:
            self.device_detail.insert("end", f"  Среднее: {rssi_stats.get('mean', 0):.1f} дБм\n")
            self.device_detail.insert("end", f"  Мин: {rssi_stats.get('min', 0):.1f} дБм\n")
            self.device_detail.insert("end", f"  Макс: {rssi_stats.get('max', 0):.1f} дБм\n")
            self.device_detail.insert("end", f"  Стд. откл: {rssi_stats.get('std', 0):.2f}\n\n")

        self.device_detail.insert("end", f"⏱️ ИНТЕРВАЛЫ\n")
        if interval_stats:
            self.device_detail.insert("end", f"  Среднее: {interval_stats.get('mean', 0)*1000:.1f} мс\n")
            self.device_detail.insert("end", f"  Мин: {interval_stats.get('min', 0)*1000:.1f} мс\n")
            self.device_detail.insert("end", f"  Макс: {interval_stats.get('max', 0)*1000:.1f} мс\n\n")

        self.device_detail.insert("end", f"🔧 PAYLOAD\n")
        self.device_detail.insert("end", f"  TX Power: {snap.get('tx_power_dbm', 'N/A')} дБм\n")
        self.device_detail.insert("end", f"  Service UUIDs: {len(snap.get('service_uuids', []))}\n")
        mfg = snap.get('manufacturer_data', {})
        self.device_detail.insert("end", f"  Manufacturer Data: {len(mfg)} записей\n")
        for cid, data in mfg.items():
            self.device_detail.insert("end", f"    {cid}: {data}\n")

        self.device_detail.insert("end", f"\n🕐 ВРЕМЯ\n")
        self.device_detail.insert("end", f"  Первый пакет: {time.strftime('%H:%M:%S', time.localtime(profile.first_seen)) if profile.first_seen else 'N/A'}\n")
        self.device_detail.insert("end", f"  Последний пакет: {time.strftime('%H:%M:%S', time.localtime(profile.last_seen)) if profile.last_seen else 'N/A'}\n")

    def _start_collection(self):
        self.is_collecting = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.lbl_status.configure(text="Статус: сбор...")

        # Очищаем профайлер
        self.profiler = DeviceProfiler(window=256)

        # Запускаем сбор в отдельном потоке
        self.collector_thread = threading.Thread(target=self._collect_loop, daemon=True)
        self.collector_thread.start()

        # Периодическое обновление GUI
        self._update_device_list_periodic()

    def _stop_collection(self):
        self.is_collecting = False
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.lbl_status.configure(text="Статус: остановлен")

        # Финальное слияние: догоняем пакеты, накопленные после
        # последнего периодического слияния в collector-потоке.
        def _final_merge():
            merge_profiles_by_mac(self.profiler)
            self._update_device_list()

        threading.Timer(2.0, _final_merge).start()

    def _collect_loop(self):

        import asyncio
        from bleak import BleakScanner

        output_path = ROOT / "data" / "raw" / "gui_capture.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)

    # Очищаем файл перед новым сбором
        if output_path.exists():
            output_path.unlink()

        self._pkts_since_merge = 0

        def collector_callback(device, adv):
            if not self.is_collecting:
                return
            record = {
                "timestamp_unix": time.time(),
                "address": device.address,
                "rssi_dbm": adv.rssi,
                "decoded": {
                    "local_name": adv.local_name,
                    "manufacturer_data": {
                        hex(k): v.hex() for k, v in adv.manufacturer_data.items()
                    },
                },
            }
            with open(output_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

            # Обрабатываем запись. Слияние профилей по MAC выполняется не на
            # каждом пакете (это лишняя нагрузка и гонка с потоком GUI), а
            # периодически — каждые 25 пакетов, плюс финальное слияние после
            # остановки сканера (см. _stop_collection).
            try:
                self.profiler.process_record(record)
            except ValueError:
                return
            self._pkts_since_merge += 1
            if self._pkts_since_merge >= 25:
                self._pkts_since_merge = 0
                merge_profiles_by_mac(self.profiler)

            # Обновляем GUI каждые 10 пакетов
            total = sum(p.packet_count for p in self.profiler.profiles.values())
            if total and total % 10 == 0:
                self.after(0, self._update_device_list)

        async def scan():
            scanner = BleakScanner(detection_callback=collector_callback)
            await scanner.start()
            while self.is_collecting:
                await asyncio.sleep(1)
            await scanner.stop()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(scan())

    def _update_device_list_periodic(self):
        """Периодическое обновление списка устройств (каждые 2 секунды)."""
        if self.is_collecting:
            self._update_device_list()
            self.after(2000, self._update_device_list_periodic)

    def _update_device_list(self):
        """Обновляет список устройств с MAC и иконками."""
        # Очищаем Treeview
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)

        # Сортируем по количеству пакетов (крупные устройства сверху)
        sorted_profiles = sorted(
            self.profiler.profiles.values(),
            key=lambda p: p.packet_count,
            reverse=True
        )

        for profile in sorted_profiles:
            icon = get_device_icon(profile.stable_snapshot)
            vendor = get_vendor_name(profile.stable_snapshot)
            name = profile.stable_snapshot.get("local_name") or vendor
            mac = profile.mac_history[0]["mac"] if profile.mac_history else "N/A"
            packets = profile.packet_count
            rssi_stats = profile.rssi_stats()
            mean_rssi = rssi_stats.get("mean", 0) if rssi_stats else 0

            self.device_tree.insert("", "end", values=(
                icon,
                name[:20],
                mac,
                packets,
                f"{mean_rssi:.1f}",
                vendor
            ))
        persist.save_profiles(sorted_profiles)
    # ------------------------------------------------------------------
    # Вкладка 2: Алерты
    # ------------------------------------------------------------------
    def _build_alerts_tab(self):
        self.alert_list = ctk.CTkTextbox(self.tab_alerts)
        self.alert_list.pack(fill="both", expand=True, padx=10, pady=10)
        self.alert_list.insert("1.0", "Алерты будут отображаться здесь после анализа...\n")

        btn_refresh = ctk.CTkButton(
            self.tab_alerts, text="🔄 Загрузить алерты", command=self._refresh_alerts
        )
        btn_refresh.pack(pady=10)

    def _refresh_alerts(self):
        self.alert_list.delete("1.0", "end")
        db.init_db()
        with db.connect() as c:
            alerts = db.list_alerts(c)
        if not alerts:
            self.alert_list.insert("1.0", "Тревог нет.\n")
            return
        for a in alerts:
            icon = "🔴" if a["level"] == "alert" else "🟡"
            self.alert_list.insert("end",
                f"{icon} [{a['level'].upper()}] {a['device']} "
                f"балл {a['score']} — {a['status']}\n")
            for r in json.loads(a["reasons_json"]):
                self.alert_list.insert("end", f"   - {r['description']}\n")
            self.alert_list.insert("end", "\n")
    # ------------------------------------------------------------------
    # Вкладка 3: Анализ файла
    # ------------------------------------------------------------------
    def _build_analysis_tab(self):
        # Выбор файла
        file_frame = ctk.CTkFrame(self.tab_analysis)
        file_frame.pack(fill="x", padx=10, pady=10)

        self.file_path_var = ctk.StringVar(value=str(ROOT / "data" / "raw" / "real_capture.jsonl"))
        entry = ctk.CTkEntry(file_frame, textvariable=self.file_path_var, width=600)
        entry.pack(side="left", padx=5)

        btn_analyze = ctk.CTkButton(
            file_frame, text="🔍 Анализировать", command=self._analyze_file
        )
        btn_analyze.pack(side="left", padx=5)

        # Результат анализа
        self.analysis_result = ctk.CTkTextbox(self.tab_analysis)
        self.analysis_result.pack(fill="both", expand=True, padx=10, pady=10)

    def _analyze_file(self):
        """Загружает JSONL, строит профили, прогоняет анализаторы."""
        file_path = Path(self.file_path_var.get())
        if not file_path.exists():
            self.analysis_result.delete("1.0", "end")
            self.analysis_result.insert("1.0", f"Файл не найден: {file_path}\n")
            return

        self.analysis_result.delete("1.0", "end")
        self.analysis_result.insert("1.0", f"Анализ файла: {file_path.name}\n\n")

        # Загружаем записи
        records = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))

        self.analysis_result.insert("end", f"Записей: {len(records)}\n")

        # Строим профили
        profiler = DeviceProfiler(window=256)
        for r in records:
            profiler.process_record(r)

        # Объединяем по MAC
        merge_profiles_by_mac(profiler)

        self.analysis_result.insert("end", f"Профилей (после объединения): {len(profiler.profiles)}\n\n")

        # Прогоняем анализаторы
        decisions = evaluate(list(profiler.profiles.values()))

        # Показываем результаты
        for d in decisions:
            if d["level"] != "none":
                icon = "🔴" if d["level"] == "alert" else "🟡"
                self.analysis_result.insert("end", f"{icon} [{d['level'].upper()}] {d['device']} (балл: {d['score']})\n")
                for r in d["reasons"]:
                    self.analysis_result.insert("end", f"   - {r['description']}\n")
                self.analysis_result.insert("end", "\n")

        if all(d["level"] == "none" for d in decisions):
            self.analysis_result.insert("end", "✅ Аномалий не обнаружено.\n")


if __name__ == "__main__":
    app = BLEMonitorApp()
    app.mainloop()