#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2026 ENCRYPTED SUPPORT LLC
## See the file COPYING for copying conditions.

"""Interactive QGraphicsView-based circuit tree visualization.

Displays Tor circuits as a left-to-right tree:
  YOU → Guard → Middle → Exit → [Proxy] → Destinations

Features:
  - Smooth bezier curved connections between nodes
  - Zoom (Ctrl+wheel) and pan (middle-drag / Ctrl+drag)
  - Animated traffic flow on active circuits (moving dashes)
  - Role-colored rounded-rect node pills
  - Click nodes/streams for details
"""

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt, QPointF, QRectF, QTimer, pyqtSignal
from PyQt5.QtGui import (QPainter, QPen, QColor, QBrush, QFont,
                          QPainterPath, QLinearGradient, QRadialGradient)
from PyQt5.QtWidgets import (QGraphicsView, QGraphicsScene,
                              QGraphicsRectItem, QGraphicsPathItem,
                              QGraphicsTextItem, QGraphicsEllipseItem,
                              QGraphicsItem, QGraphicsDropShadowEffect)


## ── Color palette ─────────────────────────────────────────
COLORS = {
    'you':       {'bg': '#E8EAF6', 'border': '#5C6BC0', 'text': '#283593'},
    'guard':     {'bg': '#E8F5E9', 'border': '#66BB6A', 'text': '#2E7D32'},
    'middle':    {'bg': '#FFF3E0', 'border': '#FFA726', 'text': '#E65100'},
    'exit':      {'bg': '#FFEBEE', 'border': '#EF5350', 'text': '#C62828'},
    'proxy':     {'bg': '#E3F2FD', 'border': '#42A5F5', 'text': '#1565C0'},
    'target':    {'bg': '#F5F5F5', 'border': '#BDBDBD', 'text': '#424242'},
    'closed':    {'bg': '#F5F5F5', 'border': '#E0E0E0', 'text': '#999999'},
    'wire_active':  '#42A5F5',
    'wire_idle':    '#E0E0E0',
    'wire_closed':  '#D0D0D0',
    'scene_bg':     '#FAFAFA',
}

## ── Layout constants ──────────────────────────────────────
NODE_W = 150
NODE_H = 40
NODE_RADIUS = 12
COL_SPACING = 60       # horizontal gap between columns
ROW_SPACING = 20       # vertical gap between rows
TARGET_W = 140
TARGET_H = 24
WIRE_WIDTH_ACTIVE = 2.5
WIRE_WIDTH_IDLE = 1.5
DASH_SPEED = 40        # px per animation tick


## ── Node graphics item ───────────────────────────────────
class NodeItem(QGraphicsRectItem):
    """Rounded-rect node pill with role color and label."""

    def __init__(self, node_data, role, active=False, parent=None):
        super().__init__(parent)
        self.node_data = node_data
        self.role = role
        self.active = active
        self._cids = set()

        pal = COLORS.get(role, COLORS['target'])
        w = NODE_W if role not in ('target', 'closed', 'you') else (
            TARGET_W if role in ('target', 'closed') else 110)
        h = NODE_H if role not in ('target', 'closed') else TARGET_H

        self.setRect(0, 0, w, h)
        self.setPen(QPen(QColor(pal['border']), 1.6))
        self.setBrush(QBrush(QColor(pal['bg'])))
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.setCursor(Qt.PointingHandCursor)

        if role not in ('target', 'closed'):
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(8)
            shadow.setColor(QColor(0, 0, 0, 40))
            shadow.setOffset(1, 2)
            self.setGraphicsEffect(shadow)

        self.setAcceptHoverEvents(True)
        self._hovered = False

        ## Build label
        self._label_item = QGraphicsTextItem(self)
        self._label_item.setDefaultTextColor(QColor(pal['text']))
        self._update_label()
        self.setToolTip(self._build_tooltip())

        if not active:
            self.setOpacity(0.55)

    def _update_label(self):
        nd = self.node_data
        role = self.role
        pal = COLORS.get(role, COLORS['target'])
        if role == 'you':
            html = ('<div style="text-align:center;">'
                    '<b style="font-size:11px;color:%s;">'
                    '\U0001f4bb YOU</b></div>' % pal['text'])
        elif role in ('target', 'closed'):
            from html import escape as _esc
            t = nd.get('target', '?')
            if len(t) > 22:
                t = t[:20] + '..'
            t = _esc(t)
            strikethrough = 'text-decoration:line-through;' \
                if role == 'closed' else ''
            html = ('<div style="font-size:9px;color:%s;%s">%s</div>'
                    % (pal['text'], strikethrough, t))
        else:
            nick = nd.get('nickname', '?')
            cc = nd.get('country', '??').upper()
            bw = nd.get('bandwidth', 0)
            if bw >= 1048576:
                bw_s = '%.1fMB' % (bw / 1048576)
            elif bw >= 1024:
                bw_s = '%.0fKB' % (bw / 1024)
            else:
                bw_s = '%dB' % bw
            role_lbl = {'guard': 'G', 'middle': 'M', 'exit': 'E',
                        'proxy': 'P'}.get(role, '?')
            html = ('<div>'
                    '<b style="font-size:10px;color:%s;">%s</b> '
                    '<b style="font-size:9px;">%s</b><br>'
                    '<span style="font-size:8px;color:#888;">'
                    '%s &middot; %s</span></div>'
                    % (pal['text'], role_lbl, nick, cc, bw_s))
        self._label_item.setHtml(html)
        r = self.rect()
        self._label_item.setTextWidth(r.width() - 6)
        th = self._label_item.boundingRect().height()
        self._label_item.setPos(3, max(0, (r.height() - th) / 2))

    def _build_tooltip(self):
        nd = self.node_data
        if self.role == 'you':
            return 'Your computer'
        if self.role == 'target':
            return nd.get('target', '?')
        fp = nd.get('fingerprint', '?')
        nick = nd.get('nickname', '?')
        cc = nd.get('country', '??')
        addr = nd.get('address', '?')
        flags = ', '.join(nd.get('flags', []))
        return '%s\n%s\nIP: %s\nCountry: %s\nFlags: %s' % (
            nick, fp, addr, cc, flags)

    def paint(self, painter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing)
        r = self.rect()
        pal = COLORS.get(self.role, COLORS['target'])
        pen = QPen(QColor(pal['border']),
                   2.2 if self._hovered else 1.6)
        painter.setPen(pen)
        bg = QColor(pal['bg'])
        if self._hovered:
            bg = bg.lighter(106)
        painter.setBrush(QBrush(bg))
        painter.drawRoundedRect(r, NODE_RADIUS, NODE_RADIUS)

    def hoverEnterEvent(self, event):
        self._hovered = True
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self._hovered = False
        self.update()
        super().hoverLeaveEvent(event)

    def center_right(self):
        r = self.rect()
        p = self.pos()
        return QPointF(p.x() + r.width(), p.y() + r.height() / 2)

    def center_left(self):
        p = self.pos()
        r = self.rect()
        return QPointF(p.x(), p.y() + r.height() / 2)

    def center(self):
        p = self.pos()
        r = self.rect()
        return QPointF(p.x() + r.width() / 2, p.y() + r.height() / 2)


## ── Curved wire between nodes ────────────────────────────
class WireItem(QGraphicsPathItem):
    """Smooth bezier curve connecting two node items."""

    def __init__(self, start_pt, end_pt, active=False, parent=None):
        super().__init__(parent)
        self.active = active
        self._start = start_pt
        self._end = end_pt
        self._phase = 0.0

        color = QColor(COLORS['wire_active'] if active
                       else COLORS['wire_idle'])
        w = WIRE_WIDTH_ACTIVE if active else WIRE_WIDTH_IDLE
        pen = QPen(color, w)
        pen.setCapStyle(Qt.RoundCap)
        if not active:
            pen.setStyle(Qt.DotLine)
        self.setPen(pen)

        self._build_path()

    def _build_path(self):
        p = QPainterPath()
        p.moveTo(self._start)
        dx = abs(self._end.x() - self._start.x()) * 0.45
        c1 = QPointF(self._start.x() + dx, self._start.y())
        c2 = QPointF(self._end.x() - dx, self._end.y())
        p.cubicTo(c1, c2, self._end)
        self.setPath(p)

    def advance_dash(self, phase):
        """Update dash offset for traffic animation."""
        if not self.active:
            return
        self._phase = phase
        pen = self.pen()
        pen.setDashPattern([6, 4])
        pen.setDashOffset(-phase)
        self.setPen(pen)


## ── Traffic flow animation dot ───────────────────────────
class FlowDot(QGraphicsEllipseItem):
    """Small dot that travels along a wire path to show traffic."""

    def __init__(self, wire_item, color=None, parent=None):
        super().__init__(-3, -3, 6, 6, parent)
        self.wire = wire_item
        c = color or QColor(COLORS['wire_active'])
        self.setBrush(QBrush(c))
        self.setPen(QPen(Qt.NoPen))
        self.setOpacity(0.85)
        self._t = 0.0

    def set_progress(self, t):
        """t in [0, 1] — position along the wire path."""
        self._t = t
        path = self.wire.path()
        pt = path.pointAtPercent(min(max(t, 0.0), 1.0))
        self.setPos(pt)


## ── Main circuit graphics view ───────────────────────────
class CircuitGraphicsView(QGraphicsView):
    """Interactive zoomable/pannable view for circuit tree."""

    node_clicked = pyqtSignal(str, str)   # (type, data)  e.g. ('node','FP'), ('stream','target')
    link_clicked = pyqtSignal(str)        # href string for compatibility

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self._scene.setBackgroundBrush(QBrush(QColor(COLORS['scene_bg'])))
        self.setScene(self._scene)

        self.setRenderHints(
            QPainter.Antialiasing | QPainter.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setMinimumHeight(200)

        self._zoom = 1.0
        self._bg_color = COLORS['scene_bg']
        self._node_items = {}   # fingerprint -> NodeItem
        self._wire_items = []
        self._flow_dots = []
        self._anim_timer = QTimer(self)
        self._anim_timer.setInterval(50)
        self._anim_timer.timeout.connect(self._animate_tick)
        self._anim_phase = 0.0
        self._last_circuits = None
        self._user_has_zoomed = False
        self._saved_transform = None
        self._saved_hscroll = 0
        self._saved_vscroll = 0

    def set_background_color(self, color_str):
        """Update scene background color (for theme switching)."""
        self._bg_color = color_str
        self._scene.setBackgroundBrush(QBrush(QColor(color_str)))

    def wheelEvent(self, event):
        """Zoom with mouse wheel — smooth, no snap-back."""
        event.accept()
        factor = 1.04
        if event.angleDelta().y() > 0:
            if self._zoom < 5.0:
                self.scale(factor, factor)
                self._zoom *= factor
        else:
            if self._zoom > 0.15:
                self.scale(1 / factor, 1 / factor)
                self._zoom /= factor
        self._user_has_zoomed = True

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            item = self.itemAt(event.pos())
            if isinstance(item, NodeItem):
                nd = item.node_data
                role = item.role
                if role == 'target':
                    cid = str(list(item._cids)[0]) if item._cids else '0'
                    self.link_clicked.emit(
                        'stream:%s:%s' % (cid, nd.get('target', '?')))
                elif role != 'you':
                    cid = str(list(item._cids)[0]) if item._cids else '0'
                    self.link_clicked.emit(
                        'node:%s:%s' % (cid, nd.get('fingerprint', '?')))
                return
            elif isinstance(item, QGraphicsTextItem):
                parent = item.parentItem()
                if isinstance(parent, NodeItem):
                    nd = parent.node_data
                    role = parent.role
                    if role == 'target':
                        cid = str(list(parent._cids)[0]) if parent._cids else '0'
                        self.link_clicked.emit(
                            'stream:%s:%s' % (cid, nd.get('target', '?')))
                    elif role != 'you':
                        cid = str(list(parent._cids)[0]) if parent._cids else '0'
                        self.link_clicked.emit(
                            'node:%s:%s' % (cid, nd.get('fingerprint', '?')))
                    return
        super().mousePressEvent(event)

    def fit_contents(self):
        """Fit the scene rect to show all items."""
        self._scene.setSceneRect(self._scene.itemsBoundingRect().adjusted(
            -20, -20, 20, 20))
        self.fitInView(self._scene.sceneRect(), Qt.KeepAspectRatio)
        self._zoom = self.transform().m11()

    ## ── Public API ────────────────────────────────────────

    def update_circuits(self, circuits, ep_running=False, ep_active=None):
        """Rebuild the circuit tree from circuits data."""
        self._last_circuits = circuits
        self._anim_timer.stop()

        ## Save user's current view state before clearing
        if self._user_has_zoomed:
            self._saved_transform = self.transform()
            self._saved_hscroll = self.horizontalScrollBar().value()
            self._saved_vscroll = self.verticalScrollBar().value()

        self._scene.clear()
        self._node_items.clear()
        self._wire_items.clear()
        self._flow_dots.clear()
        self._anim_phase = 0.0

        if not circuits:
            txt = self._scene.addText('No active circuits.',
                                      QFont('sans-serif', 11))
            txt.setDefaultTextColor(QColor('#888'))
            return

        ep_active = ep_active or {}

        ## ── Build tree: guard → chain (middles + exit + targets) ──
        tree = {}
        circ_map = {}
        max_middles = 1
        for c in circuits:
            path = c.get('path', [])
            if len(path) < 3:
                continue
            cid = c['circuit_id']
            st = c.get('status', '?')
            g = path[0]
            middles = list(path[1:-1])
            e = path[-1]
            gfp = g['fingerprint']
            chain_key = tuple(n['fingerprint'] for n in middles) + \
                (e['fingerprint'],)
            tgts = c.get('targets', [])
            has_streams = bool(tgts)
            circ_map[cid] = c
            max_middles = max(max_middles, len(middles))

            if gfp not in tree:
                tree[gfp] = {'node': g, 'chains': {}, 'active': False}
            if has_streams:
                tree[gfp]['active'] = True
            if c.get('_closed'):
                tree[gfp]['_closed'] = True

            if chain_key not in tree[gfp]['chains']:
                tree[gfp]['chains'][chain_key] = {
                    'middles': middles,
                    'exit_node': e,
                    'targets': [], 'active': False,
                    '_closed': False,
                    'status': st, 'cids': set(),
                    '_proxy_map': {}}
            ch = tree[gfp]['chains'][chain_key]
            ch['cids'].add(cid)
            if has_streams:
                ch['active'] = True
            if c.get('_closed'):
                ch['_closed'] = True
            for t in tgts:
                if t not in ch['targets']:
                    ch['targets'].append(t)
            for k, v in c.get('_proxy_map', {}).items():
                ch['_proxy_map'][k] = v

        ## ── Count rows per branch for Y positioning ──────
        def count_chain_rows(ch):
            return max(len(ch['targets']), 1)

        def count_guard_rows(g_data):
            return sum(count_chain_rows(ch)
                       for ch in g_data['chains'].values())

        total_rows = sum(count_guard_rows(gd) for gd in tree.values())
        total_rows = max(total_rows, 1)

        ## ── Column X positions (variable middle columns) ─
        x_you = 0
        x_guard = x_you + 110 + COL_SPACING
        x_mids = []
        for i in range(max_middles):
            x_mids.append(x_guard + (i + 1) * (NODE_W + COL_SPACING))
        x_exit = (x_mids[-1] if x_mids else x_guard) + NODE_W + COL_SPACING
        if ep_running:
            x_proxy = x_exit + NODE_W + COL_SPACING
            x_target = x_proxy + NODE_W + COL_SPACING
        else:
            x_proxy = None
            x_target = x_exit + NODE_W + COL_SPACING

        ## ── Sort: active circuits toward center, closed at bottom ──
        _active = [(k, v) for k, v in tree.items() if v['active']]
        _idle = [(k, v) for k, v in tree.items()
                 if not v['active'] and not v.get('_closed')]
        _closed = [(k, v) for k, v in tree.items()
                   if v.get('_closed')]
        _top_idle = _idle[:len(_idle) // 2]
        _bot_idle = _idle[len(_idle) // 2:]
        _sorted_tree = _top_idle + _active + _bot_idle + _closed

        ## ── Compute active block vertical range for centering ─
        total_h = total_rows * (TARGET_H + ROW_SPACING)
        _idle_top_rows = sum(count_guard_rows(v) for _, v in _top_idle)
        _active_rows = sum(count_guard_rows(v) for _, v in _active)
        _active_start = _idle_top_rows * (TARGET_H + ROW_SPACING)
        _active_end = _active_start + _active_rows * (TARGET_H + ROW_SPACING)
        _active_center = (_active_start + _active_end) / 2 if _active_rows \
            else total_h / 2

        ## ── Place YOU node at active center ──────────────
        you_item = NodeItem({'nickname': 'YOU'}, 'you', active=True)
        you_item.setPos(x_you, _active_center - NODE_H / 2)
        self._scene.addItem(you_item)

        ## ── Place nodes and wires ────────────────────────
        current_y = 0.0

        for gfp, gdata in _sorted_tree:
            g_rows = count_guard_rows(gdata)
            g_block_h = g_rows * (TARGET_H + ROW_SPACING)
            g_center_y = current_y + g_block_h / 2 - NODE_H / 2

            g_item = NodeItem(gdata['node'], 'guard',
                              active=gdata['active'])
            g_item._cids = set()
            for ch in gdata['chains'].values():
                g_item._cids |= ch['cids']
            g_item.setPos(x_guard, g_center_y)
            self._scene.addItem(g_item)
            self._node_items[gfp] = g_item

            ## Wire: YOU → Guard
            w = WireItem(you_item.center_right(), g_item.center_left(),
                         active=gdata['active'])
            self._scene.addItem(w)
            self._wire_items.append(w)

            chain_y = current_y
            for chain_key, ch in gdata['chains'].items():
                ch_rows = count_chain_rows(ch)
                ch_block_h = ch_rows * (TARGET_H + ROW_SPACING)
                ch_center_y = chain_y + ch_block_h / 2 - NODE_H / 2

                ## Place middle nodes (variable count)
                prev_item = g_item
                for mi, mid_node in enumerate(ch['middles']):
                    mfp = mid_node['fingerprint']
                    m_item = NodeItem(mid_node, 'middle',
                                      active=ch['active'])
                    m_item._cids = ch['cids']
                    m_item.setPos(x_mids[mi], ch_center_y)
                    self._scene.addItem(m_item)
                    _mk = '%s:%d:%s' % (mfp, mi, gfp)
                    self._node_items[_mk] = m_item

                    wm = WireItem(prev_item.center_right(),
                                  m_item.center_left(),
                                  active=ch['active'])
                    self._scene.addItem(wm)
                    self._wire_items.append(wm)
                    prev_item = m_item

                ## Place exit node
                efp = ch['exit_node']['fingerprint']
                e_item = NodeItem(ch['exit_node'], 'exit',
                                  active=ch['active'])
                e_item._cids = ch['cids']
                e_item.setPos(x_exit, ch_center_y)
                self._scene.addItem(e_item)
                _ek = '%s:%s' % (efp, ':'.join(chain_key))
                self._node_items[_ek] = e_item

                ## Wire: last middle → Exit
                we = WireItem(prev_item.center_right(),
                              e_item.center_left(),
                              active=ch['active'])
                self._scene.addItem(we)
                self._wire_items.append(we)

                ## Targets (with optional proxy nodes)
                tgts = ch['targets']
                _pmap = ch.get('_proxy_map', {})
                is_closed = ch.get('_closed', False)
                if tgts:
                    _proxy_items = {}
                    for ti, t in enumerate(tgts):
                        ty = chain_y + ti * (TARGET_H + ROW_SPACING)
                        _trole = 'closed' if is_closed else 'target'
                        t_item = NodeItem(
                            {'target': t}, _trole, active=not is_closed)
                        t_item._cids = ch['cids']
                        t_item.setPos(x_target, ty)
                        self._scene.addItem(t_item)

                        px_info = ep_active.get(t, [])
                        pn = None
                        if px_info:
                            pn = px_info[0].get('proxy', '')
                        if not pn:
                            pn = _pmap.get(t, '')
                        if ep_running and x_proxy and pn:
                            if pn not in _proxy_items:
                                _pn_short = pn
                                if '://' in _pn_short:
                                    _pn_short = _pn_short.split('://')[1]
                                if '@' in _pn_short:
                                    _pn_short = _pn_short.split('@')[1]
                                p_item = NodeItem(
                                    {'nickname': _pn_short,
                                     'country': '??',
                                     'bandwidth': 0},
                                    'proxy', active=True)
                                p_item._cids = ch['cids']
                                p_item.setPos(x_proxy, ty)
                                self._scene.addItem(p_item)
                                _proxy_items[pn] = p_item
                                w1 = WireItem(
                                    e_item.center_right(),
                                    p_item.center_left(),
                                    active=True)
                                self._scene.addItem(w1)
                                self._wire_items.append(w1)
                                dot = FlowDot(w1)
                                self._scene.addItem(dot)
                                self._flow_dots.append(dot)
                            p_item = _proxy_items[pn]
                            w = WireItem(
                                p_item.center_right(),
                                t_item.center_left(),
                                active=True)
                        else:
                            _wire_active = not is_closed
                            w = WireItem(
                                    e_item.center_right(),
                                    t_item.center_left(),
                                    active=_wire_active)
                        self._scene.addItem(w)
                        self._wire_items.append(w)
                        if not is_closed:
                            dot = FlowDot(w)
                            self._scene.addItem(dot)
                            self._flow_dots.append(dot)
                else:
                    st = ch.get('status', '?')
                    idle_item = NodeItem(
                        {'target': '%s idle' % st}, 'target',
                        active=False)
                    idle_item._cids = ch['cids']
                    idle_item.setPos(x_target, chain_y)
                    self._scene.addItem(idle_item)
                    w = WireItem(
                        e_item.center_right(),
                        idle_item.center_left(),
                        active=False)
                    self._scene.addItem(w)
                    self._wire_items.append(w)

                chain_y += ch_block_h

            current_y += g_block_h

        ## Update scene rect and restore or fit view
        self._scene.setSceneRect(
            self._scene.itemsBoundingRect().adjusted(-30, -30, 30, 30))

        if self._user_has_zoomed and self._saved_transform is not None:
            ## Restore user's zoom/pan position
            self.setTransform(self._saved_transform)
            QTimer.singleShot(0, lambda: (
                self.horizontalScrollBar().setValue(self._saved_hscroll),
                self.verticalScrollBar().setValue(self._saved_vscroll)))
        else:
            ## First render — fit everything
            self.fitInView(self._scene.sceneRect(), Qt.KeepAspectRatio)
            self._zoom = max(self.transform().m11(), 0.2)

        if self._flow_dots:
            self._anim_timer.start()

    def _animate_tick(self):
        """Advance traffic flow animation."""
        self._anim_phase += 0.04
        if self._anim_phase > 1.0:
            self._anim_phase = 0.0

        ## Move flow dots along their wires
        for dot in self._flow_dots:
            dot.set_progress(self._anim_phase)

        ## Animate active wire dash offsets
        for wire in self._wire_items:
            if wire.active:
                wire.advance_dash(self._anim_phase * 30)

    def get_status_text(self, circuits):
        """Return summary text for the header."""
        if not circuits:
            return 'No active circuits.'
        n_built = sum(1 for c in circuits if c.get('status') == 'BUILT')
        n_building = len(circuits) - n_built
        return '%d built, %d building (%d total)' % (
            n_built, n_building, len(circuits))
