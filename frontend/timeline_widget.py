from dataclasses import dataclass
from typing import Callable, Optional

from PySide6.QtGui import (
    QPen,
    QColor,
    QPainter,
    QAction,
    QWheelEvent,
    QMouseEvent,
    QPaintEvent,
)
from PySide6.QtWidgets import QSizePolicy, QWidget, QHBoxLayout, QMenu, QToolBar
from PySide6.QtCore import Qt, QPoint

from core import Ctx


class OptionalRange:
    def __init__(self) -> None:
        self._min: Optional[int] = None
        self._max: Optional[int] = None

    @property
    def is_valid(self) -> bool:
        return self._min is not None and self._max is not None

    @property
    def min(self) -> int:
        if self._min is None:
            raise RuntimeError("Cannot access min: OptionalRange is invalid.")
        return self._min

    @property
    def max(self) -> int:
        if self._max is None:
            raise RuntimeError("Cannot access max: OptionalRange is invalid.")
        return self._max

    def clone(self) -> "OptionalRange":
        clone = OptionalRange()
        clone._min = self._min
        clone._max = self._max
        return clone

    def set(self, new_min: int, new_max: int) -> None:
        if new_min > new_max:
            raise RuntimeError("Invalid OptionalRange")
        self._min = new_min
        self._max = new_max

    def invalidate(self) -> None:
        self._min = None
        self._max = None


@dataclass
class DragState:
    start_time: int = -1
    current_time: int = -1
    is_dragging: bool = False


class TimelineBar(QWidget):
    ctx: Ctx
    is_local: bool
    bound_min: int
    bound_max: int
    selection: OptionalRange
    drag: DragState
    selection_callback: Callable[[OptionalRange], None]

    def __init__(
        self,
        ctx: Ctx,
        is_local: bool,
        selection_callback: Callable[[OptionalRange], None],
    ) -> None:
        super().__init__()
        self.ctx = ctx
        self.is_local = is_local
        self.selection_callback = selection_callback

        self.bound_min = 0
        self.bound_max = 0

        self.selection = OptionalRange()
        self.drag = DragState()

        self.setMinimumSize(32, 32)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def get_bounds(self) -> tuple[int, int]:
        if self.is_local:
            return self.bound_min, self.bound_max
        else:
            # Bounds of the global bar is always the full range
            return self.ctx.db.time_bbox

    def set_bounds(self, time_min: int, time_max: int) -> None:
        if not self.is_local:
            raise Exception("cannot set bound on the global bar")
        self.bound_min = time_min
        self.bound_max = time_max
        self.update()

    def _y_to_time(self, y: float) -> int:
        bound_min, bound_max = self.get_bounds()
        return bound_min + int((y / self.height()) * (bound_max - bound_min))

    def _time_to_y(self, time: int) -> int:
        bound_min, bound_max = self.get_bounds()
        return int(((time - bound_min) / (bound_max - bound_min)) * self.height())

    def wheelEvent(self, event: QWheelEvent) -> None:
        if event.angleDelta().y() == 0:
            return
        delta = -1 if event.angleDelta().y() > 0 else 1
        self.ctx.set_time(self.ctx.db.time + delta)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            time = self._y_to_time(event.position().y())
            self.drag.start_time = time
            self.drag.current_time = time
            self.drag.is_dragging = False
            self.update()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if event.buttons() & Qt.MouseButton.LeftButton:
            self.drag.is_dragging = True
            self.drag.current_time = self._y_to_time(event.position().y())
            self.update()

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.MouseButton.LeftButton:
            return

        if not self.drag.is_dragging or self.drag.start_time == self.drag.current_time:
            self.ctx.set_time(self.drag.start_time)

            if self.selection.is_valid:
                if self.selection.min <= self.drag.start_time <= self.selection.max:
                    self.selection.invalidate()
                    self.selection_callback(self.selection.clone())
        else:
            drag_min = min(self.drag.start_time, self.drag.current_time)
            drag_max = max(self.drag.start_time, self.drag.current_time)
            self.selection.set(drag_min, drag_max)
            self.selection_callback(self.selection.clone())

        self.drag.is_dragging = False
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.fillRect(self.rect(), Qt.GlobalColor.lightGray)

        bound_min, bound_max = self.get_bounds()
        time = self.ctx.db.time

        # Calculate coordinates for drawing the selection / drag rect
        if self.drag.is_dragging:
            start_time = min(self.drag.start_time, self.drag.current_time)
            end_time = max(self.drag.start_time, self.drag.current_time)
            if start_time != end_time:
                y_start = self._time_to_y(start_time)
                y_end = self._time_to_y(end_time)
                painter.fillRect(
                    0, y_start, self.width(), y_end - y_start, QColor(0, 0, 255, 64)
                )
        elif self.selection.is_valid:
            y_start = self._time_to_y(self.selection.min)
            y_end = self._time_to_y(self.selection.max)
            painter.fillRect(
                0, y_start, self.width(), y_end - y_start, QColor(0, 0, 255, 64)
            )

        if bound_min <= time <= bound_max:
            y = self._time_to_y(time)
            painter.setPen(QPen(Qt.GlobalColor.red, 2, Qt.PenStyle.SolidLine))
            painter.drawLine(0, y, self.width(), y)


class TimelineWidget(QWidget):
    ctx: Ctx
    local_bar: TimelineBar
    global_bar: TimelineBar
    _action_close_trace: QAction

    def __init__(self, ctx: Ctx) -> None:
        super().__init__()
        self.ctx = ctx
        self.ctx.register_time_observer(self)
        self.setup_user_interface()
        self.on_time_update()

    def close(self) -> bool:
        if super().close():
            self.ctx.unregister_time_observer(self)
            return True
        return False

    def setup_user_interface(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)

        self._initialize_context_menu()

        self.local_bar = TimelineBar(self.ctx, True, self.on_local_selection)
        self.global_bar = TimelineBar(self.ctx, False, self.on_global_selection)

        self.local_bar.hide()

        layout.addWidget(self.local_bar)
        layout.addWidget(self.global_bar)
        self.setLayout(layout)

    def _initialize_context_menu(self) -> None:
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu_handler)
        self._action_close_trace = QAction("Close trace", self)

    def _context_menu_handler(self, position: QPoint) -> None:
        menu = QMenu(self)
        menu.addAction(self._action_close_trace)

        if menu.exec(self.mapToGlobal(position)) == self._action_close_trace:
            self.ctx.close_db()

    def on_global_selection(self, selection: OptionalRange) -> None:
        if not selection.is_valid:
            self.local_bar.hide()
            self.global_bar.selection.invalidate()
        else:
            self.local_bar.set_bounds(selection.min, selection.max)
            self.local_bar.selection.invalidate()
            self.local_bar.show()

    def on_local_selection(self, sel: OptionalRange) -> None:
        if sel.is_valid:
            self.local_bar.set_bounds(sel.min, sel.max)
            self.local_bar.selection.invalidate()
            self.global_bar.selection.set(sel.min, sel.max)
        else:
            self.local_bar.hide()
            self.global_bar.selection.invalidate()

        self.global_bar.update()

    def on_time_update(self) -> None:
        self.local_bar.update()
        self.global_bar.update()


class TimelineDock(QToolBar):
    widget: TimelineWidget

    def __init__(self, ctx: Ctx) -> None:
        super().__init__()
        self.widget = TimelineWidget(ctx)
        self.setMovable(False)
        self.setContentsMargins(0, 0, 0, 0)
        self.addWidget(self.widget)
