from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QTableWidgetItem,
    QWidget,
    QTableWidget,
    QVBoxLayout,
)

from core import Ctx
from frinet_db import SearchResult


class SearchResultsWidget(QWidget):
    ctx: Ctx
    results: list[SearchResult]

    def __init__(self, ctx: Ctx, results: list[SearchResult]):
        super().__init__()
        self.ctx = ctx
        self.results = results

        self.setup_ui()

    def setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        self.table = QTableWidget(self)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(
            ["Start Address", "End Address", "Time Min", "Time Max", "Context"]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        layout.addWidget(self.table)
        self.populate()

        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)

    def populate(self) -> None:
        self.table.setRowCount(len(self.results))
        for row, result in enumerate(self.results):
            addr_min = result.addr_min
            addr_max = result.addr_max
            time_min = result.time_min
            time_max = result.time_max

            # Fetch context data around the search result
            num_bytes_visible = 32
            base_addr = max(0, addr_min - 8)

            context_str = ""
            data = self.ctx.db.memory_bytes_at(time_min, base_addr, num_bytes_visible)
            if data:
                ascii_parts = []
                hex_parts = []
                for val in data:
                    if val is not None:
                        hex_parts.append(f"{val:02X}")
                        ascii_parts.append(chr(val) if 0x20 <= val <= 0x7E else ".")
                    else:
                        hex_parts.append("??")
                        ascii_parts.append(".")
                context_str = f"{''.join(ascii_parts)}  [{' '.join(hex_parts)}]"

            mono_font = QFont("monospace", 10)
            mono_font.setStyleHint(QFont.StyleHint.Monospace)

            context_item = QTableWidgetItem(context_str)
            context_item.setFont(mono_font)

            self.table.setItem(row, 0, QTableWidgetItem(f"0x{addr_min:08X}"))
            self.table.setItem(row, 1, QTableWidgetItem(f"0x{addr_max:08X}"))
            self.table.setItem(row, 2, QTableWidgetItem(str(time_min)))
            self.table.setItem(row, 3, QTableWidgetItem(str(time_max)))
            self.table.setItem(row, 4, context_item)

    def on_item_double_clicked(self, item: QTableWidgetItem) -> None:
        row = item.row()
        result = self.results[row]
        self.ctx.set_time(result.time_min)
