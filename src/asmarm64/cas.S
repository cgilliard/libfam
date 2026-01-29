.global cas128
cas128:
c.0:	ldp	x11, x10, [x1]
c.1:	ldaxp	x9, x8, [x0]
   cmp	x9, x11
   cset	w12, ne
   cmp	x8, x10
   cinc	w12, w12, ne
   cbz	w12, c.2;
   stlxp	w12, x9, x8, [x0]
   cbnz	w12, c.1;
   b	c.3;
c.2:	stlxp	w12, x2, x3, [x0]
   cbnz	w12, 0;
c.3:	cmp	x9, x11
   ccmp	x8, x10, #0x0, eq
   cset	w0, eq
   b.eq	c.4;
   stp	x9, x8, [x1]
c.4:	ret
