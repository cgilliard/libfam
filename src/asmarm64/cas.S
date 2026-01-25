.global cas128
cas128:
cas128cbnz:	ldp	x11, x10, [x1]
cas128start:	ldaxp	x9, x8, [x0]
   cmp	x9, x11
   cset	w12, ne
   cmp	x8, x10
   cinc	w12, w12, ne
   cbz	w12, cas128cbz;
   stlxp	w12, x9, x8, [x0]
   cbnz	w12, cas128start;
   b	cas128b;
cas128cbz:	stlxp	w12, x2, x3, [x0]
   cbnz	w12, cas128cbnz;
cas128b:	cmp	x9, x11
   ccmp	x8, x10, #0x0, eq
   cset	w0, eq
   b.eq	cas128complete;
cas128stp:	stp	x9, x8, [x1]
cas128complete:	ret
