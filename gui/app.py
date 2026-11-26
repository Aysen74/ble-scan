"""
Главное окно приложения BLE Privacy Monitor.

Упрощённая версия без графиков (matplotlib).
Три вкладки: Мониторинг, Алерты, Анализ файла.
"""

import json
import threading
import time
from pathlib import Path

import customtkinter as ctk

# Добавляем корень проекта в sys.path
import sys
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from profiles.device_profile import DeviceProfiler
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
        self.geometry("1200x800")
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

        self.lbl_status = ctk.CTkLabel(btn_frame, text="Статус: неактивен")
        self.lbl_status.pack(side="right", padx=5)

        # Список устройств (текстовое поле с прокруткой)
        self.device_list = ctk.CTkTextbox(self.tab_monitor, width=600)
        self.device_list.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        self.device_list.insert("1.0", "Нажмите 'Начать сбор' для сканирования эфира...\n")

        # Информация о выбранном устройстве
        info_frame = ctk.CTkFrame(self.tab_monitor, width=400)
        info_frame.pack(side="right", fill="y", padx=10, pady=10)
        info_frame.pack_propagate(False)

        ctk.CTkLabel(info_frame, text="Детали устройства", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        self.device_info = ctk.CTkTextbox(info_frame)
        self.device_info.pack(fill="both", expand=True, padx=5, pady=5)
        self.device_info.insert("1.0", "Выберите устройство из списка слева для просмотра деталей.\n")

    def _start_collection(self):
        self.is_collecting = True
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.lbl_status.configure(text="Статус: сбор...")
        self.device_list.delete("1.0", "end")
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

    def _collect_loop(self):
        """Цикл сбора: использует BleakScanner напрямую."""
        import asyncio
        from bleak import BleakScanner

        output_path = ROOT / "data" / "raw" / "gui_capture.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Очищаем файл перед новым сбором
        if output_path.exists():
            output_path.unlink()

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
            self.profiler.process_record(record)

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
        self.device_list.delete("1.0", "end")
        self.device_list.insert("1.0", f"Найдено профилей: {len(self.profiler.profiles)}\n\n")

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

            self.device_list.insert("end", f"{icon} {name}\n")
            self.device_list.insert("end", f"   MAC: {mac}\n")
            self.device_list.insert("end", f"   Пакетов: {packets} | RSSI: {mean_rssi:.1f} дБм\n")
            self.device_list.insert("end", f"   Производитель: {vendor}\n\n")

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
        """Загружает алерты из файла и показывает их."""
        alert_path = ROOT / "data" / "alerts" / "alerts.jsonl"
        if not alert_path.exists():
            self.alert_list.delete("1.0", "end")
            self.alert_list.insert("1.0", "Файл алертов не найден.\n")
            return

        self.alert_list.delete("1.0", "end")
        with open(alert_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    alert = json.loads(line)
                    level = alert.get("level", "unknown")
                    device = alert.get("device", "unknown")
                    score = alert.get("score", 0)
                    reasons = alert.get("reasons", [])

                    icon = "🔴" if level == "alert" else "🟡"
                    self.alert_list.insert("end", f"{icon} [{level.upper()}] {device} (балл: {score})\n")
                    for r in reasons:
                        self.alert_list.insert("end", f"   - {r.get('description', '')}\n")
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

        self.analysis_result.insert("end", f"Профилей: {len(profiler.profiles)}\n\n")

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