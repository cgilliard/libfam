.global cas128
cas128:
0:	ldp	x11, x10, [x1]
1:	ldaxp	x9, x8, [x0]
   cmp	x9, x11
   cset	w12, ne
   cmp	x8, x10
   cinc	w12, w12, ne
   cbz	w12, 2;
   stlxp	w12, x9, x8, [x0]
   cbnz	w12, 1;
   b	3;
2:	stlxp	w12, x2, x3, [x0]
   cbnz	w12, 0;
3:	cmp	x9, x11
   ccmp	x8, x10, #0x0, eq
   cset	w0, eq
   b.eq	4;
   stp	x9, x8, [x1]
4:	ret
