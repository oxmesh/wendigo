/**
 * Wendigo SVG Diagram Renderer v4
 * Zero-overlap memory corruption visualizations.
 *
 * Design rules enforced in every renderer:
 *   - 40px padding on all sides (PAD)
 *   - curY cursor tracks vertical position — nothing hardcoded
 *   - Minimum 20px vertical gap between text elements (MIN_GAP)
 *   - SVG height is ALWAYS set dynamically via _updateSvgHeight at the end
 *   - text-anchor: start/middle/end chosen to prevent horizontal bleed
 *   - Labels that would overlap are stacked vertically (row offset)
 *   - Overflow zone / small regions get abbreviated text or none
 */

const COLORS = {
    allocated: '#3fb950', freed: '#f85149', dangling: '#e3b341',
    overflow: '#f85149', target: '#58a6ff', metadata: '#bc8cff',
    unmapped: '#484f58', mapped: '#21262d', crash: '#f85149',
    bg: '#0d1117', bg2: '#161b22', bg3: '#21262d', border: '#30363d',
    text: '#e6edf3', textDim: '#8b949e', accent: '#58a6ff',
    purple: '#bc8cff', cyan: '#39d2c0', orange: '#d29922',
    green: '#3fb950', red: '#f85149', yellow: '#e3b341',
};
const PAD = 40;     // universal padding on all sides
const MIN_GAP = 20; // minimum vertical gap between text rows

class DiagramRenderer {
    constructor(container) {
        this.container = container;
        this.tooltip = document.getElementById('tooltip');
        this.ns = 'http://www.w3.org/2000/svg';
    }

    render(vizData) {
        this.container.innerHTML = '';
        const dt = vizData.diagram_type;
        const hasLinear = vizData.elements && vizData.elements.some(e => e.type === 'heap_linear');
        const r = {
            heap_oob: () => hasLinear ? this.renderHeapLinear(vizData) : this.renderGeneric(vizData),
            uaf_timeline: () => this.renderUAFTimeline(vizData),
            double_free: () => this.renderDoubleFree(vizData),
            stack_layout: () => this.renderStackLayout(vizData),
            memory_map: () => this.renderMemoryMap(vizData),
            generic: () => this.renderGeneric(vizData),
        };
        (r[dt] || r.generic)();
    }

    // ─── SVG Helpers ───────────────────────────────────────
    _svg(w, h) {
        const s = document.createElementNS(this.ns, 'svg');
        s.setAttribute('width', '100%'); s.setAttribute('height', h);
        s.setAttribute('viewBox', `0 0 ${w} ${h}`);
        s.style.overflow = 'visible'; s.style.maxWidth = w + 'px';
        this.container.appendChild(s); return s;
    }
    _fin(svg, h) {
        svg.setAttribute('height', h);
        const v = svg.getAttribute('viewBox').split(' ');
        svg.setAttribute('viewBox', `${v[0]} ${v[1]} ${v[2]} ${h}`);
    }
    _g(svg, cls) { const g = document.createElementNS(this.ns, 'g'); if (cls) g.setAttribute('class', cls); svg.appendChild(g); return g; }
    _rect(p, x, y, w, h, fill, stroke, rx) {
        const r = document.createElementNS(this.ns, 'rect');
        r.setAttribute('x', x); r.setAttribute('y', y);
        r.setAttribute('width', Math.max(w, 0)); r.setAttribute('height', Math.max(h, 0));
        r.setAttribute('fill', fill || 'none');
        if (stroke) { r.setAttribute('stroke', stroke); r.setAttribute('stroke-width', '1.5'); }
        if (rx) r.setAttribute('rx', rx); p.appendChild(r); return r;
    }
    _text(p, x, y, text, o = {}) {
        const t = document.createElementNS(this.ns, 'text');
        t.setAttribute('x', x); t.setAttribute('y', y);
        t.setAttribute('fill', o.fill || COLORS.text);
        t.setAttribute('font-size', o.size || '13');
        t.setAttribute('font-family', o.sans ? "-apple-system, sans-serif" : "'SF Mono','Fira Code','Cascadia Code',monospace");
        if (o.anchor) t.setAttribute('text-anchor', o.anchor);
        if (o.weight) t.setAttribute('font-weight', o.weight);
        if (o.baseline) t.setAttribute('dominant-baseline', o.baseline);
        if (o.opacity) t.setAttribute('opacity', o.opacity);
        t.textContent = text; p.appendChild(t); return t;
    }
    _line(p, x1, y1, x2, y2, color, w, dash) {
        const l = document.createElementNS(this.ns, 'line');
        l.setAttribute('x1', x1); l.setAttribute('y1', y1); l.setAttribute('x2', x2); l.setAttribute('y2', y2);
        l.setAttribute('stroke', color || COLORS.border); l.setAttribute('stroke-width', w || '1.5');
        if (dash) l.setAttribute('stroke-dasharray', dash); p.appendChild(l); return l;
    }
    _path(p, d, stroke, fill, w) {
        const e = document.createElementNS(this.ns, 'path');
        e.setAttribute('d', d); e.setAttribute('stroke', stroke || 'none');
        e.setAttribute('fill', fill || 'none'); if (w) e.setAttribute('stroke-width', w);
        p.appendChild(e); return e;
    }
    _arrow(p, x1, y1, x2, y2, color) {
        const id = 'ah_' + Math.random().toString(36).substr(2, 6);
        const defs = document.createElementNS(this.ns, 'defs');
        const m = document.createElementNS(this.ns, 'marker');
        m.setAttribute('id', id); m.setAttribute('markerWidth', '10'); m.setAttribute('markerHeight', '7');
        m.setAttribute('refX', '9'); m.setAttribute('refY', '3.5'); m.setAttribute('orient', 'auto');
        const poly = document.createElementNS(this.ns, 'polygon');
        poly.setAttribute('points', '0 0, 10 3.5, 0 7'); poly.setAttribute('fill', color || COLORS.overflow);
        m.appendChild(poly); defs.appendChild(m); p.appendChild(defs);
        const l = this._line(p, x1, y1, x2, y2, color || COLORS.overflow, '2');
        l.setAttribute('marker-end', `url(#${id})`); return l;
    }
    _addHover(el, text) {
        const tt = this.tooltip; el.style.cursor = 'pointer';
        el.addEventListener('mouseenter', e => { tt.style.display = 'block'; tt.innerHTML = text.replace(/\n/g, '<br>'); tt.style.left = (e.pageX+12)+'px'; tt.style.top = (e.pageY-10)+'px'; });
        el.addEventListener('mousemove', e => { tt.style.left = (e.pageX+12)+'px'; tt.style.top = (e.pageY-10)+'px'; });
        el.addEventListener('mouseleave', () => { tt.style.display = 'none'; });
    }
    _rotatedText(p, cx, cy, text, fill, size) {
        const t = this._text(p, cx, cy, text, { fill, size: size||'9', anchor: 'middle', baseline: 'middle' });
        t.setAttribute('transform', `rotate(-90, ${cx}, ${cy})`); return t;
    }
    _badge(p, x, y, text, bg, fg, w) {
        const bw = w || (text.length * 8 + 16);
        this._rect(p, x-bw/2, y-10, bw, 20, bg, null, 10);
        this._text(p, x, y+4, text, { anchor:'middle', size:'11', weight:'bold', fill: fg||'#fff' });
    }
    _tick(p, x, y, c) { this._line(p, x, y-4, x, y+4, c, '1.5'); }
    _addStripeDef(svg, id, color, angle) {
        const d = svg.querySelector('defs') || (() => { const dd = document.createElementNS(this.ns, 'defs'); svg.insertBefore(dd, svg.firstChild); return dd; })();
        const pat = document.createElementNS(this.ns, 'pattern');
        pat.setAttribute('id', id); pat.setAttribute('width', '8'); pat.setAttribute('height', '8');
        pat.setAttribute('patternUnits', 'userSpaceOnUse'); pat.setAttribute('patternTransform', `rotate(${angle||-45})`);
        const l = document.createElementNS(this.ns, 'line');
        l.setAttribute('x1','0'); l.setAttribute('y1','0'); l.setAttribute('x2','0'); l.setAttribute('y2','8');
        l.setAttribute('stroke', color||'rgba(248,81,73,0.2)'); l.setAttribute('stroke-width','4');
        pat.appendChild(l); d.appendChild(pat);
    }
    _addGlowFilter(svg, id) {
        const d = svg.querySelector('defs') || (() => { const dd = document.createElementNS(this.ns, 'defs'); svg.insertBefore(dd, svg.firstChild); return dd; })();
        const f = document.createElementNS(this.ns, 'filter');
        f.setAttribute('id', id); f.setAttribute('x','-50%'); f.setAttribute('y','-50%'); f.setAttribute('width','200%'); f.setAttribute('height','200%');
        const b = document.createElementNS(this.ns, 'feGaussianBlur'); b.setAttribute('stdDeviation','3'); b.setAttribute('result','glow'); f.appendChild(b);
        const mg = document.createElementNS(this.ns, 'feMerge');
        const m1 = document.createElementNS(this.ns, 'feMergeNode'); m1.setAttribute('in','glow');
        const m2 = document.createElementNS(this.ns, 'feMergeNode'); m2.setAttribute('in','SourceGraphic');
        mg.appendChild(m1); mg.appendChild(m2); f.appendChild(mg); d.appendChild(f);
    }
    // Place labels along a line, stacking vertically on overlap
    _placeLabels(svg, labels, baseY) {
        const CW = 7; // approx char width at size 10
        labels.sort((a, b) => a.x - b.x);
        // assign default anchors: first=start, last=end, middle=middle
        labels.forEach((l, i) => {
            if (labels.length === 1) l.anchor = l.anchor || 'middle';
            else if (i === 0) l.anchor = 'start';
            else if (i === labels.length - 1) l.anchor = 'end';
            else l.anchor = l.anchor || 'middle';
            l.row = 0;
        });
        // detect horizontal overlap, bump to next row
        for (let i = 1; i < labels.length; i++) {
            const prev = labels[i - 1], cur = labels[i];
            const prevEnd = prev.anchor === 'start' ? prev.x + prev.text.length * CW :
                            prev.anchor === 'end' ? prev.x : prev.x + prev.text.length * CW / 2;
            const tw = cur.text.length * CW;
            const curStart = cur.anchor === 'start' ? cur.x :
                             cur.anchor === 'end' ? cur.x - tw : cur.x - tw / 2;
            if (curStart - prevEnd < 12 && cur.row === prev.row) cur.row = prev.row + 1;
        }
        let maxRow = 0;
        labels.forEach(l => {
            const yOff = l.row * 18;
            maxRow = Math.max(maxRow, l.row);
            this._text(svg, l.x, baseY + 16 + yOff, l.text, { anchor: l.anchor, size: '10', fill: l.color });
            if (l.sub) this._text(svg, l.x, baseY + 30 + yOff, l.sub, { anchor: l.anchor, size: '9', fill: l.subColor || l.color });
        });
        return baseY + 34 + maxRow * 18;
    }

    // ═══════════════════════════════════════════════════════
    // 1. HEAP BUFFER OVERFLOW — Linear Layout
    // ═══════════════════════════════════════════════════════
    renderHeapLinear(viz) {
        const d = viz.elements.find(e => e.type === 'heap_linear');
        if (!d) return this.renderGeneric(viz);
        const W = 860;
        const svg = this._svg(W, 600); // generous; will shrink
        this._addStripeDef(svg, 'overflow-stripes', 'rgba(248,81,73,0.15)');
        this._addGlowFilter(svg, 'red-glow');

        const barW = W - PAD * 2 - 50, metaW = 22;
        const totalSpan = d.region_size + Math.max(d.overflow_bytes, 1);
        let rr = Math.max(0.25, Math.min(0.75, d.region_size / totalSpan));
        const regionW = rr * barW;
        const overflowW = Math.max(barW - regionW, 80); // min 80px
        const regionX = PAD + metaW + 2;
        const overflowX = regionX + regionW;
        const metaRX = overflowX + overflowW + 2;

        let Y = PAD;

        // Title
        this._text(svg, W/2, Y, `HEAP BUFFER ${d.access_type==='WRITE'?'OVERFLOW':'OOB READ'}`,
            { anchor:'middle', size:'18', weight:'bold', fill:COLORS.text, sans:true });
        const sev = viz.severity||d.severity;
        this._badge(svg, W-PAD-10, Y-4, sev, sev==='CRITICAL'?'#da3633':sev==='HIGH'?'#f85149':COLORS.orange);
        Y += MIN_GAP;
        const sub = d.is_write
            ? `${d.access_size}B write corrupts ${d.overflow_bytes}B past allocation boundary`
            : `${d.access_size}B read leaks data ${d.overflow_bytes}B past allocation`;
        this._text(svg, W/2, Y, sub, { anchor:'middle', size:'12', fill:COLORS.textDim, sans:true });
        Y += MIN_GAP;

        // Alloc info
        if (d.alloc_func) {
            this._text(svg, regionX+4, Y, `allocated by ${d.alloc_func}()`, { size:'10', fill:COLORS.textDim });
            Y += 16;
        }

        // BOUNDARY label
        Y += 4;
        const blW = 76;
        this._rect(svg, overflowX-blW/2, Y-10, blW, 16, 'rgba(255,255,255,0.08)', 'rgba(255,255,255,0.25)', 3);
        this._text(svg, overflowX, Y+2, 'BOUNDARY', { anchor:'middle', size:'9', weight:'bold', fill:'#fff' });
        Y += 14;

        // Byte ruler — ticks BELOW the line
        const rulerY = Y;
        this._line(svg, regionX, rulerY, regionX+regionW+overflowW, rulerY, 'rgba(255,255,255,0.08)', '1');
        const ticks = [
            { x: regionX, label: '0' },
            { x: overflowX, label: `${d.region_size}` },
            { x: regionX+regionW+overflowW, label: `${d.region_size+d.overflow_bytes}` },
        ];
        if (regionW > 140) ticks.push({ x: regionX+regionW/2, label: `${Math.round(d.region_size/2)}` });
        ticks.forEach(t => {
            this._line(svg, t.x, rulerY-3, t.x, rulerY+3, 'rgba(255,255,255,0.25)', '1');
            this._text(svg, t.x, rulerY+14, t.label, { anchor:'middle', size:'9', fill:COLORS.textDim });
        });
        Y = rulerY + MIN_GAP + 4;

        // Main bar
        const barY = Y, barH = 72;
        // Left metadata
        this._rect(svg, PAD, barY, metaW, barH, 'rgba(188,140,255,0.10)', COLORS.purple, 2);
        this._rotatedText(svg, PAD+metaW/2, barY+barH/2, 'HDR', COLORS.purple, 9);
        this._addHover(this._rect(svg, PAD, barY, metaW, barH, 'transparent'), 'Heap chunk header\n(size, flags — 16 bytes)');

        // Allocated region
        const rg = this._g(svg, 'region');
        this._rect(rg, regionX, barY, regionW, barH, 'rgba(63,185,80,0.08)', COLORS.allocated);
        this._addHover(this._rect(rg, regionX, barY, regionW, barH, 'transparent'),
            `Allocated buffer\nSize: ${d.region_size.toLocaleString()} bytes\n${d.alloc_func?'Allocator: '+d.alloc_func+'()':''}`);
        if (regionW > 100) {
            this._text(rg, regionX+regionW/2, barY+28, 'Allocated Buffer', { anchor:'middle', size:'13', weight:'600', fill:COLORS.allocated, sans:true });
            this._text(rg, regionX+regionW/2, barY+48, `${d.region_size.toLocaleString()} bytes`, { anchor:'middle', size:'12', fill:COLORS.textDim });
        } else {
            this._text(rg, regionX+regionW/2, barY+barH/2+4, `${d.region_size}B`, { anchor:'middle', size:'11', fill:COLORS.allocated });
        }

        // Boundary dashed line
        this._line(svg, overflowX, barY-4, overflowX, barY+barH+4, 'rgba(255,255,255,0.6)', '2', '5,3');

        // Overflow zone
        const og = this._g(svg, 'overflow-zone');
        this._rect(og, overflowX, barY, overflowW, barH, 'rgba(248,81,73,0.15)', COLORS.overflow);
        this._rect(og, overflowX, barY, overflowW, barH, 'url(#overflow-stripes)');
        this._addHover(this._rect(og, overflowX, barY, overflowW, barH, 'transparent'),
            `Overflow zone\n${d.access_type} of ${d.access_size.toLocaleString()} bytes\n${d.crash_func?'Triggered by: '+d.crash_func+'()':''}`);
        if (overflowW >= 110) {
            this._text(og, overflowX+overflowW/2, barY+28, d.is_write?'⚠ CORRUPTED':'OOB READ',
                { anchor:'middle', size:'13', weight:'bold', fill:COLORS.overflow, sans:true });
            this._text(og, overflowX+overflowW/2, barY+48, `${d.access_size.toLocaleString()}B ${d.access_type.toLowerCase()}`,
                { anchor:'middle', size:'12', fill:'rgba(248,81,73,0.7)' });
        } else if (overflowW >= 50) {
            this._text(og, overflowX+overflowW/2, barY+barH/2+4, d.is_write?'⚠':'OOB',
                { anchor:'middle', size:'11', weight:'bold', fill:COLORS.overflow, sans:true });
        }

        // Right metadata
        if (d.is_write) {
            this._rect(svg, metaRX, barY, metaW, barH, 'rgba(248,81,73,0.20)', COLORS.overflow, 2);
            this._addStripeDef(svg, 'hdr-stripes', 'rgba(248,81,73,0.3)');
            this._rect(svg, metaRX, barY, metaW, barH, 'url(#hdr-stripes)', null, 2);
            this._rotatedText(svg, metaRX+metaW/2, barY+barH/2, 'HDR ⚠', COLORS.overflow, 9);
            this._addHover(this._rect(svg, metaRX, barY, metaW, barH, 'transparent'),
                '⚠ Next chunk header CORRUPTED\nHeap metadata corruption →\npotential arbitrary write via unlink');
        } else {
            this._rect(svg, metaRX, barY, metaW, barH, 'rgba(188,140,255,0.06)', COLORS.border, 2);
            this._rotatedText(svg, metaRX+metaW/2, barY+barH/2, 'HDR', COLORS.textDim, 9);
        }

        Y = barY + barH + 16;

        // Overflow arrow
        const ax1 = regionX+regionW*0.55, ax2 = overflowX+Math.min(overflowW*0.85, overflowW-5);
        const amx = (ax1+ax2)/2, amy = Y+20;
        const ap = this._path(svg, `M ${ax1} ${Y} Q ${amx} ${amy} ${ax2} ${Y}`, COLORS.overflow, 'none', '2.5');
        ap.setAttribute('class', 'overflow-arrow');
        const ahId = 'ah_m_'+Math.random().toString(36).substr(2,4);
        const defs = svg.querySelector('defs');
        const mk = document.createElementNS(this.ns, 'marker');
        mk.setAttribute('id',ahId); mk.setAttribute('markerWidth','10'); mk.setAttribute('markerHeight','7');
        mk.setAttribute('refX','9'); mk.setAttribute('refY','3.5'); mk.setAttribute('orient','auto');
        const po = document.createElementNS(this.ns, 'polygon');
        po.setAttribute('points','0 0, 10 3.5, 0 7'); po.setAttribute('fill', COLORS.overflow);
        mk.appendChild(po); defs.appendChild(mk); ap.setAttribute('marker-end', `url(#${ahId})`);

        // Arrow label BELOW curve
        const lbl = (d.crash_func ? `${d.crash_func}() → ` : '') + `${d.access_type} ${d.access_size.toLocaleString()}B overflow`;
        this._text(svg, amx, Y+36, lbl, { anchor:'middle', size:'11', weight:'bold', fill:COLORS.overflow });
        Y += 52;

        // Address line
        this._line(svg, regionX, Y, metaRX+metaW, Y, 'rgba(255,255,255,0.06)', '1');
        const addrs = [];
        const same = d.access_addr === d.region_end_addr;
        if (d.region_start_addr && d.region_start_addr !== '0x0') {
            this._tick(svg, regionX, Y, COLORS.purple);
            addrs.push({ x: regionX, text: d.region_start_addr, color: COLORS.purple });
        }
        if (d.region_end_addr && d.region_end_addr !== '0x0') {
            const c = same ? COLORS.overflow : 'rgba(255,255,255,0.6)';
            this._tick(svg, overflowX, Y, c);
            addrs.push({ x: overflowX, text: d.region_end_addr, color: c, sub: same?'↑ crash':null, subColor: COLORS.overflow });
        }
        if (d.access_addr && d.access_addr !== '0x0' && !same) {
            const cx = regionX+regionW+overflowW;
            this._tick(svg, cx, Y, COLORS.overflow);
            addrs.push({ x: cx, text: d.access_addr, color: COLORS.overflow, sub: '↑ crash', subColor: COLORS.overflow });
        }
        Y = this._placeLabels(svg, addrs, Y) + PAD;
        this._fin(svg, Y);
    }

    // ═══════════════════════════════════════════════════════
    // 2. USE-AFTER-FREE — Timeline
    // ═══════════════════════════════════════════════════════
    renderUAFTimeline(viz) {
        const events = viz.elements.filter(e => e.type === 'timeline_event').sort((a,b) => a.order - b.order);
        const chunk = viz.elements.find(e => e.type === 'chunk');
        const W = 860, cardH = 110, gap = 14;
        const svg = this._svg(W, 800);
        this._addGlowFilter(svg, 'danger-glow');

        let Y = PAD;
        this._text(svg, W/2, Y, 'USE-AFTER-FREE TIMELINE', { anchor:'middle', size:'18', weight:'bold', fill:COLORS.text, sans:true });
        Y += MIN_GAP;
        this._text(svg, W/2, Y, 'Dangling pointer accesses freed memory — attacker can control contents',
            { anchor:'middle', size:'12', fill:COLORS.textDim, sans:true });
        Y += MIN_GAP + 4;

        const cardW = W - PAD*2 - 20, cardX = PAD + 10;
        const chunkW = Math.min(200, cardW * 0.3), chunkX = cardX + cardW - chunkW - 20;
        const textMaxX = chunkX - 16; // text must not go past here

        const phases = {
            allocated: { bg:'rgba(63,185,80,0.06)', border:COLORS.green, chunk:'rgba(63,185,80,0.15)', label:'LIVE' },
            freed:     { bg:'rgba(248,81,73,0.06)', border:COLORS.red, chunk:'rgba(248,81,73,0.15)', label:'FREED' },
            dangling:  { bg:'rgba(227,179,65,0.06)', border:COLORS.yellow, chunk:'rgba(227,179,65,0.15)', label:'DANGLING' },
        };

        events.forEach((evt, i) => {
            const ph = phases[evt.state] || phases.allocated;
            const g = this._g(svg, 'phase-card');
            this._rect(g, cardX, Y, cardW, cardH, ph.bg, ph.border, 6);

            // Phase circle
            const cx = cardX+30, cy = Y+cardH/2;
            const c = document.createElementNS(this.ns, 'circle');
            c.setAttribute('cx',cx); c.setAttribute('cy',cy); c.setAttribute('r','16');
            c.setAttribute('fill', ph.border); c.setAttribute('opacity','0.9'); g.appendChild(c);
            this._text(g, cx, cy+5, evt.order.toString(), { anchor:'middle', size:'14', weight:'bold', fill:'#fff' });

            // Text — clipped to textMaxX via truncation
            const tx = cardX + 60;
            this._text(g, tx, Y+28, evt.label, { size:'14', weight:'600', fill:COLORS.text, sans:true });
            if (evt.function) this._text(g, tx, Y+48, `${evt.function}()`, { size:'13', fill:ph.border });
            if (evt.source) {
                const src = evt.source.length > 40 ? '…'+evt.source.slice(-38) : evt.source;
                this._text(g, tx, Y+66, src, { size:'11', fill:COLORS.textDim });
            }

            // Chunk state box (right side of card)
            const ckY = Y+15, ckH = cardH-30;
            this._rect(g, chunkX, ckY, chunkW, ckH, ph.chunk, ph.border, 4);
            this._text(g, chunkX+chunkW/2, ckY+22, `Chunk: ${ph.label}`, { anchor:'middle', size:'12', weight:'bold', fill:ph.border, sans:true });
            if (evt.state === 'allocated') {
                for (let j=0;j<4;j++) this._rect(g, chunkX+10, ckY+32+j*8, (chunkW-20)*(0.3+Math.random()*0.7), 5, 'rgba(63,185,80,0.25)', null, 2);
            } else if (evt.state === 'freed') {
                this._text(g, chunkX+chunkW/2, ckY+44, 'fd → next_free', { anchor:'middle', size:'10', fill:'rgba(248,81,73,0.6)' });
                this._text(g, chunkX+chunkW/2, ckY+58, 'bk → prev_free', { anchor:'middle', size:'10', fill:'rgba(248,81,73,0.6)' });
            } else if (evt.state === 'dangling' && chunk) {
                const aOff = chunk.offset||0;
                const aW = Math.max((chunk.access_size/Math.max(chunk.size,1))*(chunkW-20), 12);
                const aX = chunkX+10+(aOff/Math.max(chunk.size,1))*(chunkW-20);
                this._rect(g, Math.min(aX, chunkX+chunkW-aW-10), ckY+36, aW, 20, 'rgba(227,179,65,0.35)', COLORS.yellow, 3);
                this._text(g, chunkX+chunkW/2, ckY+50, `${chunk.access_type||'READ'} ${chunk.access_size}B`, { anchor:'middle', size:'9', fill:COLORS.yellow, weight:'bold' });
            }
            this._addHover(this._rect(g, cardX, Y, cardW, cardH, 'transparent'),
                `Phase ${evt.order}: ${evt.label}\n${evt.function?'Function: '+evt.function+'()':''}\n${evt.source||''}`);

            Y += cardH;
            if (i < events.length-1) {
                this._text(svg, W/2, Y+gap/2+3, '▼', { anchor:'middle', size:'16', fill:(phases[events[i+1].state]||ph).border, sans:true });
                Y += gap;
            }
        });

        Y += MIN_GAP;

        // Danger callout
        const dg = this._g(svg, 'danger-box');
        this._rect(dg, cardX, Y, cardW, 80, 'rgba(248,81,73,0.05)', 'rgba(248,81,73,0.3)', 6);
        this._rect(dg, cardX, Y, 4, 80, COLORS.red);
        this._text(dg, cardX+24, Y+22, '⚠ EXPLOITATION POTENTIAL', { size:'13', weight:'bold', fill:COLORS.red, sans:true });
        this._text(dg, cardX+24, Y+42, 'Freed memory can be reclaimed by attacker-controlled allocation (heap spray / feng shui)',
            { size:'11', fill:COLORS.textDim, sans:true });
        this._text(dg, cardX+24, Y+60, `Next malloc(${chunk?chunk.size:'?'}) returns this slot → attacker controls the "object"`,
            { size:'11', fill:'rgba(248,81,73,0.7)', sans:true });
        Y += 80 + PAD;
        this._fin(svg, Y);
    }

    // ═══════════════════════════════════════════════════════
    // 3. DOUBLE FREE — Freelist Corruption
    // ═══════════════════════════════════════════════════════
    renderDoubleFree(viz) {
        const events = viz.elements.filter(e => e.type === 'timeline_event').sort((a,b) => a.order-b.order);
        const freelist = viz.elements.find(e => e.type === 'freelist');
        const W = 860;
        const svg = this._svg(W, 700);
        this._addGlowFilter(svg, 'red-glow');

        let Y = PAD;
        this._text(svg, W/2, Y, 'DOUBLE FREE', { anchor:'middle', size:'18', weight:'bold', fill:COLORS.red, sans:true });
        Y += MIN_GAP;
        this._text(svg, W/2, Y, 'Same chunk freed twice → freelist corruption → arbitrary write primitive',
            { anchor:'middle', size:'12', fill:COLORS.textDim, sans:true });
        Y += MIN_GAP + 10;

        // Horizontal timeline
        const tlX1 = PAD+60, tlX2 = W-PAD-60;
        this._line(svg, tlX1, Y, tlX2, Y, COLORS.border, '2', '6,4');
        events.forEach((evt, i) => {
            const cx = tlX1 + (i/Math.max(events.length-1,1))*(tlX2-tlX1);
            const c = document.createElementNS(this.ns, 'circle');
            c.setAttribute('cx',cx); c.setAttribute('cy',Y); c.setAttribute('r','18');
            c.setAttribute('fill', evt.color);
            c.setAttribute('stroke', evt.state==='double_free'?'#fff':'rgba(255,255,255,0.3)');
            c.setAttribute('stroke-width', evt.state==='double_free'?'3':'1.5');
            if (evt.state==='double_free') c.setAttribute('filter','url(#red-glow)');
            svg.appendChild(c);
            this._text(svg, cx, Y+5, evt.order.toString(), { anchor:'middle', size:'13', fill:'#fff', weight:'bold' });
            this._text(svg, cx, Y+38, evt.label, { anchor:'middle', size:'11', fill:COLORS.text, sans:true });
            if (evt.function) this._text(svg, cx, Y+54, `${evt.function}()`, { anchor:'middle', size:'10', fill:COLORS.textDim });
            this._addHover(c, `${evt.label}\n${evt.function?evt.function+'()':''}`);
        });
        Y += 70;

        if (!freelist) { this._fin(svg, Y+PAD); return; }

        // Freelist — scale nodes to fit
        this._text(svg, W/2, Y, '── FREELIST STATE ──', { anchor:'middle', size:'13', weight:'bold', fill:COLORS.textDim, sans:true });
        Y += MIN_GAP;
        const entries = freelist.entries;
        const maxNodeW = 160, nodeH = 50, nodeGap = 30;
        // Scale down if too many nodes
        const totalNeeded = entries.length*(maxNodeW+nodeGap)-nodeGap;
        const avail = W - PAD*2;
        const scale = Math.min(1, avail/totalNeeded);
        const nodeW = Math.max(80, maxNodeW*scale);
        const adjGap = Math.max(16, nodeGap*scale);
        const flW = entries.length*(nodeW+adjGap)-adjGap;
        const flX = (W-flW)/2;

        entries.forEach((entry, i) => {
            const nx = flX + i*(nodeW+adjGap);
            const dup = entry.highlight;
            const g = this._g(svg);
            this._rect(g, nx, Y, nodeW, nodeH, dup?'rgba(248,81,73,0.15)':'rgba(255,255,255,0.03)', dup?COLORS.red:COLORS.border, 6);
            if (dup) { this._addStripeDef(svg, `fl-s-${i}`, 'rgba(248,81,73,0.12)'); this._rect(g, nx, Y, nodeW, nodeH, `url(#fl-s-${i})`, null, 6); }
            // Addr — truncate if node is small
            const addrText = nodeW < 100 ? (entry.addr.length>10 ? entry.addr.slice(0,8)+'…' : entry.addr) : entry.addr;
            this._rect(g, nx+6, Y+8, nodeW-12, 14, 'rgba(255,255,255,0.03)', 'rgba(255,255,255,0.1)', 3);
            this._text(g, nx+nodeW/2, Y+19, addrText, { anchor:'middle', size: nodeW<100?'8':'10', fill:dup?COLORS.red:COLORS.text });
            this._text(g, nx+nodeW/2, Y+42, entry.label||'', { anchor:'middle', size: nodeW<100?'8':'10', fill:dup?COLORS.red:COLORS.textDim, weight:dup?'bold':'normal', sans:true });
            this._addHover(this._rect(g, nx, Y, nodeW, nodeH, 'transparent'),
                `Freelist entry\nAddress: ${entry.addr}\nState: ${entry.state}${dup?'\n⚠ DUPLICATE — corruption!':''}`);
            if (i < entries.length-1) this._arrow(svg, nx+nodeW, Y+nodeH/2, nx+nodeW+adjGap, Y+nodeH/2, dup?COLORS.red:COLORS.textDim);
        });
        Y += nodeH + MIN_GAP + 10;

        // Consequence
        this._line(svg, PAD+40, Y, W-PAD-40, Y, 'rgba(255,255,255,0.06)', '1');
        Y += MIN_GAP;
        this._text(svg, W/2, Y, '⚠ CONSEQUENCE', { anchor:'middle', size:'14', weight:'bold', fill:COLORS.red, sans:true });
        Y += MIN_GAP + 6;

        const boxW = 180, boxH = 60;
        const b1x = W/2-boxW-40, b2x = W/2+40;
        this._rect(svg, b1x, Y, boxW, boxH, 'rgba(88,166,255,0.08)', COLORS.accent, 6);
        this._text(svg, b1x+boxW/2, Y+22, 'ptr_a = malloc(N)', { anchor:'middle', size:'12', fill:COLORS.accent, sans:true });
        this._text(svg, b1x+boxW/2, Y+42, 'legitimate object', { anchor:'middle', size:'10', fill:COLORS.textDim, sans:true });
        this._rect(svg, b2x, Y, boxW, boxH, 'rgba(248,81,73,0.08)', COLORS.red, 6);
        this._text(svg, b2x+boxW/2, Y+22, 'ptr_b = malloc(N)', { anchor:'middle', size:'12', fill:COLORS.red, sans:true });
        this._text(svg, b2x+boxW/2, Y+42, 'attacker-controlled', { anchor:'middle', size:'10', fill:'rgba(248,81,73,0.7)', sans:true });

        const tcX = W/2-70, tcY = Y+boxH+PAD;
        this._rect(svg, tcX, tcY, 140, 40, 'rgba(227,179,65,0.12)', COLORS.yellow, 6);
        this._text(svg, W/2, tcY+24, 'SAME CHUNK', { anchor:'middle', size:'12', weight:'bold', fill:COLORS.yellow, sans:true });
        this._arrow(svg, b1x+boxW/2, Y+boxH, tcX+40, tcY, COLORS.accent);
        this._arrow(svg, b2x+boxW/2, Y+boxH, tcX+100, tcY, COLORS.red);
        Y = tcY + 40 + MIN_GAP;
        this._text(svg, W/2, Y, 'Two pointers to same memory → type confusion / arbitrary write', { anchor:'middle', size:'11', fill:COLORS.textDim, sans:true });
        Y += PAD;
        this._fin(svg, Y);
    }

    // ═══════════════════════════════════════════════════════
    // 4. STACK BUFFER OVERFLOW — Vertical Stack Frame
    // ═══════════════════════════════════════════════════════
    renderStackLayout(viz) {
        const slots = viz.elements.filter(e => e.type === 'stack_slot');
        const arrows = viz.elements.filter(e => e.type === 'arrow');
        const ad = arrows[0] || {};

        const slotH = 52, slotW = 360, padL = 80;
        const W = 740; // wide enough for badges
        const svg = this._svg(W, 800);
        this._addStripeDef(svg, 'smash-stripes', 'rgba(248,81,73,0.18)');
        this._addGlowFilter(svg, 'danger-glow');

        let Y = PAD;
        this._text(svg, W/2, Y, 'STACK FRAME LAYOUT', { anchor:'middle', size:'18', weight:'bold', fill:COLORS.text, sans:true });
        Y += MIN_GAP;
        this._text(svg, W/2, Y, 'High addresses at top — overflow grows upward toward return address',
            { anchor:'middle', size:'12', fill:COLORS.textDim, sans:true });
        Y += MIN_GAP + 4;

        const slotsY = Y;
        // HIGH/LOW labels — outside the slots, left side with padding
        this._text(svg, padL-14, slotsY+14, '↑ HIGH', { anchor:'end', size:'10', fill:COLORS.textDim, sans:true });
        this._text(svg, padL-14, slotsY+slots.length*slotH-4, '↓ LOW', { anchor:'end', size:'10', fill:COLORS.textDim, sans:true });

        const targetIdx = slots.findIndex(s => s.is_target);
        const retSmashed = slots.find(s => s.label === 'Return Address' && s.smashed);

        // Overflow arrow on far left
        if (slots.some(s => s.smashed) && targetIdx >= 0) {
            const arrowX = padL - 40;
            const firstSmashed = slots.findIndex(s => s.smashed);
            const ay1 = slotsY + targetIdx*slotH + slotH/2;
            const ay2 = slotsY + firstSmashed*slotH + slotH/2;
            const p = this._path(svg, `M ${arrowX} ${ay1} L ${arrowX} ${ay2}`, COLORS.overflow, 'none', '2.5');
            p.setAttribute('class', 'overflow-arrow');
            const ahId = 'ah_s_'+Math.random().toString(36).substr(2,4);
            const d = svg.querySelector('defs') || document.createElementNS(this.ns, 'defs');
            if (!svg.querySelector('defs')) svg.insertBefore(d, svg.firstChild);
            const mk = document.createElementNS(this.ns, 'marker');
            mk.setAttribute('id',ahId); mk.setAttribute('markerWidth','10'); mk.setAttribute('markerHeight','7');
            mk.setAttribute('refX','5'); mk.setAttribute('refY','3.5'); mk.setAttribute('orient','auto');
            const po = document.createElementNS(this.ns, 'polygon');
            po.setAttribute('points','0 0, 10 3.5, 0 7'); po.setAttribute('fill', COLORS.overflow);
            mk.appendChild(po); d.appendChild(mk); p.setAttribute('marker-end', `url(#${ahId})`);
            if (ad.distance) this._text(svg, arrowX-8, (ay1+ay2)/2+4, `${ad.distance}B`, { anchor:'end', size:'10', fill:COLORS.overflow, weight:'bold' });
        }

        // Render slots
        const badgeX = padL + slotW + 20; // right-side annotation column
        slots.forEach((slot, i) => {
            const y = slotsY + i*slotH;
            const g = this._g(svg, 'stack-slot');
            let fill = 'rgba(255,255,255,0.02)', border = COLORS.border, tc = COLORS.text;
            if (slot.is_target) { fill='rgba(88,166,255,0.08)'; border=COLORS.target; tc=COLORS.accent; }
            if (slot.smashed) { fill='rgba(248,81,73,0.12)'; border=COLORS.overflow; tc=COLORS.overflow; }
            this._rect(g, padL, y, slotW, slotH-4, fill, border, 4);
            if (slot.smashed) this._rect(g, padL, y, slotW, slotH-4, 'url(#smash-stripes)', null, 4);

            // Label (left) — truncate if slot name is long
            const label = slot.label.length > 30 ? slot.label.slice(0,28)+'…' : slot.label;
            this._text(g, padL+14, y+slotH/2+1, label, { size:'13', fill:tc, weight:(slot.smashed||slot.is_target)?'600':'normal' });

            // Size (right, inside box) — ensure it doesn't overlap label
            this._text(g, padL+slotW-14, y+slotH/2+1, `${slot.size}B`, { anchor:'end', size:'11', fill:COLORS.textDim });

            // Right-side annotations — one per slot, NO overlap
            if (slot.is_target) {
                this._text(g, badgeX, y+slotH/2+1, '← BUFFER', { size:'12', fill:COLORS.accent, weight:'bold', sans:true });
            } else if (slot.smashed && slot.label === 'Return Address') {
                // RIP CONTROL badge REPLACES "SMASHED" text entirely
                // (rendered after the loop for proper z-order)
            } else if (slot.smashed) {
                this._text(g, badgeX, y+slotH/2+1, '← SMASHED', { size:'12', fill:COLORS.overflow, weight:'bold', sans:true });
            }
            this._addHover(this._rect(g, padL, y, slotW, slotH-4, 'transparent'),
                `${slot.label}\nSize: ${slot.size} bytes${slot.smashed?'\n⚠ OVERWRITTEN by overflow':''}${slot.is_target?'\nTarget buffer (overflow source)':''}`);
        });

        // RIP CONTROL badge — drawn last, on top, with glow
        if (retSmashed) {
            const ri = slots.indexOf(retSmashed);
            const ry = slotsY + ri*slotH;
            const bw = 160, bh = 32;
            const bx = badgeX, by = ry + (slotH-4-bh)/2;
            // Triple-layer glow
            const o = this._rect(svg, bx-4, by-4, bw+8, bh+8, 'rgba(248,81,73,0.12)', null, 18);
            o.setAttribute('filter','url(#danger-glow)');
            this._rect(svg, bx-1, by-1, bw+2, bh+2, 'rgba(248,81,73,0.30)', null, 16).setAttribute('filter','url(#danger-glow)');
            this._rect(svg, bx, by, bw, bh, 'rgba(248,81,73,0.92)', null, 16);
            this._text(svg, bx+bw/2, by+bh/2+5, '⚠ RIP CONTROL', { anchor:'middle', size:'13', weight:'bold', fill:'#fff', sans:true });
        }

        Y = slotsY + slots.length*slotH + MIN_GAP;
        if (ad.label) {
            this._text(svg, W/2, Y, ad.label, { anchor:'middle', size:'12', fill:COLORS.overflow, weight:'bold' });
            Y += MIN_GAP;
        }
        Y += PAD - MIN_GAP;
        this._fin(svg, Y);
    }

    // ═══════════════════════════════════════════════════════
    // 5. NULL DEREFERENCE / SEGV — Memory Map
    // ═══════════════════════════════════════════════════════
    renderMemoryMap(viz) {
        const map = viz.elements.find(e => e.type === 'memory_map');
        if (!map) return this.renderGeneric(viz);
        const regions = map.regions;
        const W = 680;
        const regionH = 56, gap = 8;
        const svg = this._svg(W, 600);
        this._addGlowFilter(svg, 'red-glow');
        const barW = W - PAD*2 - 140, barX = PAD + 120; // 120px for left address labels

        let Y = PAD;
        this._text(svg, W/2, Y, map.is_null_deref ? 'NULL POINTER DEREFERENCE' : 'SEGMENTATION FAULT',
            { anchor:'middle', size:'18', weight:'bold', fill:COLORS.text, sans:true });
        Y += MIN_GAP;
        if (map.is_null_deref && !map.is_write) this._badge(svg, W/2, Y, 'LIKELY NOT EXPLOITABLE', COLORS.green, '#000', 190);
        else if (map.is_null_deref && map.is_write) this._badge(svg, W/2, Y, 'NULL WRITE — INVESTIGATE', COLORS.orange, '#000', 200);
        Y += MIN_GAP;
        if (map.crash_func) { this._text(svg, W/2, Y, `Crashed in ${map.crash_func}()`, { anchor:'middle', size:'11', fill:COLORS.textDim }); Y += 16; }
        Y += 8;

        regions.forEach((region, i) => {
            let fill, border, tc;
            if (region.state === 'unmapped') { fill='rgba(72,79,88,0.20)'; border=COLORS.unmapped; tc=COLORS.textDim; }
            else if (region.state === 'crash') { fill='rgba(248,81,73,0.12)'; border=COLORS.crash; tc=COLORS.crash; }
            else { fill='rgba(255,255,255,0.02)'; border=COLORS.border; tc=COLORS.text; }

            const g = this._g(svg);
            this._rect(g, barX, Y, barW, regionH, fill, border, 4);

            // Address label — left, end-anchored, with enough room
            this._text(g, barX-12, Y+regionH/2+4, region.start, { anchor:'end', size:'10', fill:COLORS.purple });

            // Icon + label — inside box with left padding to clear icon
            const icon = region.icon || '';
            const labelX = barX + (icon ? 28 : 14);
            if (icon) this._text(g, barX+12, Y+24, icon, { size:'14', sans:true });
            this._text(g, labelX, Y+24, region.label, { size:'13', fill:tc, sans:true });

            if (region.end) {
                this._text(g, labelX, Y+42, `${region.start} — ${region.end}`, { size:'10', fill:COLORS.textDim });
            }

            // Crash pin — inside box, right side, with clearance from CRASH text
            if (region.state === 'crash') {
                const pinX = barX+barW-24, pinY = Y+regionH/2;
                const pin = document.createElementNS(this.ns, 'circle');
                pin.setAttribute('cx',pinX); pin.setAttribute('cy',pinY); pin.setAttribute('r','8');
                pin.setAttribute('fill',COLORS.crash); pin.setAttribute('filter','url(#red-glow)');
                g.appendChild(pin);
                this._text(g, pinX, pinY+4, '✕', { anchor:'middle', size:'10', fill:'#fff', weight:'bold' });
                // CRASH label — left of pin with gap
                this._text(g, pinX-18, pinY+4, '← CRASH', { anchor:'end', size:'12', fill:COLORS.crash, weight:'bold', sans:true });
            }
            this._addHover(this._rect(g, barX, Y, barW, regionH, 'transparent'),
                `${region.label}\nRange: ${region.start}${region.end?' — '+region.end:''}\nState: ${region.state}${region.access_type?'\nAccess: '+region.access_type:''}`);
            Y += regionH + gap;
        });
        Y += PAD - gap;
        this._fin(svg, Y);
    }

    // ═══════════════════════════════════════════════════════
    // 6. GENERIC — Fallback Info Card
    // ═══════════════════════════════════════════════════════
    renderGeneric(viz) {
        const info = viz.elements.find(e => e.type === 'info_box');
        const W = 600;
        const svg = this._svg(W, 300);
        let Y = PAD;

        this._rect(svg, PAD, Y-10, W-PAD*2, 10, 'transparent'); // spacer for top padding
        this._text(svg, W/2, Y+10, viz.bug_type || 'Unknown Bug Type', { anchor:'middle', size:'17', weight:'bold', fill:COLORS.accent, sans:true });
        Y += 36;
        if (viz.severity) {
            const sc = viz.severity==='CRITICAL'?COLORS.red:viz.severity==='HIGH'?'#da3633':viz.severity==='MEDIUM'?COLORS.orange:COLORS.green;
            this._badge(svg, W/2, Y, viz.severity, sc);
            Y += MIN_GAP + 6;
        }
        if (info) {
            // Card background
            this._rect(svg, PAD+10, Y-8, W-PAD*2-20, Object.keys(info.details||{}).length*28+16, 'rgba(255,255,255,0.02)', COLORS.border, 8);
            for (const [k, v] of Object.entries(info.details || {})) {
                this._text(svg, PAD+30, Y+8, k + ':', { size:'12', fill:COLORS.textDim, sans:true });
                this._text(svg, PAD+160, Y+8, String(v), { size:'12', fill:COLORS.text });
                Y += 28;
            }
            Y += 8;
        }
        if (viz.access_type) {
            Y += 8;
            this._text(svg, W/2, Y, `${viz.access_type} of ${viz.access_size||'?'} bytes at ${viz.access_address||'N/A'}`,
                { anchor:'middle', size:'12', fill:COLORS.textDim });
            Y += MIN_GAP;
        }
        Y += PAD;
        this._fin(svg, Y);
    }
}

// ─── CSS ────────────────────────────────────────────────
(function injectDiagramCSS() {
    if (document.getElementById('wendigo-diagram-css')) return;
    const s = document.createElement('style'); s.id = 'wendigo-diagram-css';
    s.textContent = `
        .overflow-arrow { transition: stroke-width .2s; stroke-dasharray: 1000; stroke-dashoffset: 0; }
        .overflow-arrow:hover { stroke-width: 4; stroke-dasharray: 8 4; animation: arrow-flow .6s linear infinite; }
        @keyframes arrow-flow { to { stroke-dashoffset: -12; } }
        .phase-card rect:first-child { transition: opacity .2s; }
        .phase-card:hover rect:first-child { opacity: .85; }
        .stack-slot rect:first-child { transition: opacity .15s; }
        .stack-slot:hover rect:first-child { opacity: .9; }
        .svg-tooltip { font-family: 'SF Mono','Fira Code',monospace; line-height: 1.5; white-space: pre-line; }
        .stack-frame-controlled { background: rgba(248,81,73,.08) !important; border-left: 3px solid #f85149; padding-left: 5px !important; }
        .frame-addr-controlled { color: #f85149 !important; font-weight: 600; }
        .frame-func-controlled { color: #f85149 !important; opacity: .7; }
        .frame-controlled-tag { display:inline-block; background:rgba(248,81,73,.85); color:#fff; font-size:9px; font-weight:700; padding:1px 6px; border-radius:3px; margin-left:8px; font-family:-apple-system,sans-serif; letter-spacing:.5px; vertical-align:middle; }
    `;
    document.head.appendChild(s);
})();

// ─── Init + loadReport ──────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const c = document.getElementById('diagram-container');
    if (!c) return;
    window.renderer = new DiagramRenderer(c);
    const d = document.getElementById('report-data');
    if (d && d.textContent.trim()) { try { loadReport(JSON.parse(d.textContent)); } catch(e) { console.error('Parse error:', e); } }
});

function loadReport(data) {
    const report = data.report, analysis = data.analysis, viz = data.visualization;
    const _s = (id, t) => { const e = document.getElementById(id); if (e) e.textContent = t; };
    const _e = id => document.getElementById(id);

    _s('bug-type', report.bug_type || 'Unknown');
    _s('bug-category', report.bug_category || 'Unknown');
    _s('access-info', `${report.access_type||'?'} of ${report.access_size||'?'} bytes`);
    _s('address', report.access_address || 'N/A');
    _s('score', analysis.score + '/100');
    _s('one-liner', analysis.one_liner);

    const badge = _e('severity-badge');
    if (badge) { badge.textContent = analysis.severity; badge.className = 'severity-badge severity-' + analysis.severity.replace(/\s+/g, '-'); }

    const fl = _e('factors-list');
    if (fl) { fl.innerHTML = ''; analysis.factors.forEach(f => { const li = document.createElement('li'); li.textContent = f; fl.appendChild(li); }); }

    // Stack trace with pattern highlighting
    const te = _e('stack-trace');
    if (te) {
        te.innerHTML = '';
        const pats = ['0x4141414141414141','0x4242424242424242','0x4343434343434343','0x4444444444444444','0x4545454545454545','0x4646464646464646','0x4747474747474747','0x4848484848484848','0x41414141','0x42424242','0x43434343','0x44444444'];
        const isPat = a => { if (!a) return false; const s = String(a).toLowerCase(); return pats.some(p=>s===p) || /^0x([0-9a-f])\1{7,15}$/.test(s); };

        (report.crash_trace || []).forEach(frame => {
            const div = document.createElement('div');
            const ctrl = isPat(frame.address);
            div.className = 'stack-frame' + (ctrl?' stack-frame-controlled':'');
            let loc = '';
            if (frame.source_file) loc = `<span class="frame-loc">${frame.source_file}:${frame.line}</span>`;
            else if (frame.module) loc = `<span class="frame-loc">(${frame.module})</span>`;
            div.innerHTML = `<span class="frame-num">#${frame.frame_num}</span>
                <span class="${ctrl?'frame-addr frame-addr-controlled':'frame-addr'}">${frame.address}</span>
                <span class="${ctrl?'frame-func frame-func-controlled':'frame-func'}">${frame.function||'??'}</span>
                ${loc}${ctrl?'<span class="frame-controlled-tag">CONTROLLED</span>':''}`;
            te.appendChild(div);
        });
    }

    const hs = _e('heap-traces');
    if (hs && report.heap_info) {
        hs.classList.remove('hidden');
        const hi = report.heap_info;
        _s('heap-summary', `${hi.region_size}B region, access ${hi.offset}B ${hi.direction}, state: ${hi.chunk_state||'N/A'}`);
        const rt = (frames, el) => { if(!el)return; el.innerHTML=''; (frames||[]).forEach(f => { const d=document.createElement('div'); d.className='stack-frame'; d.innerHTML=`<span class="frame-num">#${f.frame_num}</span><span class="frame-addr">${f.address}</span><span class="frame-func">${f.function||'??'}</span>`; el.appendChild(d); }); };
        rt(hi.alloc_trace, _e('alloc-trace'));
        rt(hi.free_trace, _e('free-trace'));
    } else if (hs) { hs.classList.add('hidden'); }

    if (window.renderer && viz) window.renderer.render(viz);
    const up = _e('upload-section'), rp = _e('report-section');
    if (up) up.classList.add('hidden');
    if (rp) rp.classList.remove('hidden');
}

function handleUpload() {
    const fi = document.getElementById('log-file'), ti = document.getElementById('log-text');
    const fd = new FormData();
    if (fi && fi.files.length > 0) fd.append('log_file', fi.files[0]);
    else if (ti && ti.value.trim()) fd.append('log_text', ti.value);
    else { alert('Please provide an ASAN log file or paste output.'); return; }
    fetch('/analyze', { method:'POST', body:fd }).then(r=>r.json()).then(d => { if(d.error){alert(d.error);return;} loadReport(d); }).catch(e=>alert('Error: '+e.message));
}
function exportPNG() {
    const s = document.querySelector('#diagram-container svg');
    if (!s) { alert('No diagram'); return; }
    const d = new XMLSerializer().serializeToString(s);
    const c = document.createElement('canvas'), ctx = c.getContext('2d'), img = new Image();
    img.onload = () => { c.width=img.width*2; c.height=img.height*2; ctx.scale(2,2); ctx.fillStyle='#0d1117'; ctx.fillRect(0,0,c.width,c.height); ctx.drawImage(img,0,0); c.toBlob(b=>{const u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download='wendigo-diagram.png';a.click();URL.revokeObjectURL(u);},'image/png'); };
    img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(d)));
}
function newAnalysis() { const u=document.getElementById('upload-section'),r=document.getElementById('report-section'); if(u)u.classList.remove('hidden'); if(r)r.classList.add('hidden'); }
function exportHTML() { const h=document.documentElement.outerHTML,b=new Blob([h],{type:'text/html'}),u=URL.createObjectURL(b),a=document.createElement('a');a.href=u;a.download='wendigo-report.html';a.click();URL.revokeObjectURL(u); }

