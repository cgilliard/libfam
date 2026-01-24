
.global __cas128_arm64
__cas128_arm64:
    ldp     x11, x10, [x1]          // x11:x10 = *expected

retry:
    ldaxp   x9,  x8,  [x0]          // linked load (x9 = lo, x8 = hi)

    cmp     x9,  x11
    cset    w12, ne
    cmp     x8,  x10
    cinc    w12, w12, ne            // w12 != 0 if any part differs

    cbz     w12, do_store
    b       fail_writeback          // early out - already different

do_store:
    stlxp   w12, x2,  x3,  [x0]     // try storing desired
    cbnz    w12, retry              // exclusive monitor failed → retry from ldaxp

    // At this point we know we stored successfully.
    // But we must check whether value really was what we expected
    // (ABA / spurious failure handling)
    cmp     x9, x11
    ccmp    x8, x10, #0, eq
    cset    w0, eq                  // w0 = 1 only if still matched

    b.eq    1f                      // was really equal → success, skip writeback

fail_writeback:
    stp     x9, x8, [x1]            // write observed value back to *expected
    mov     w0, #0

1:
    ret

/*
    ldp	x11, x10, [x1]
    ldaxp	x9, x8, [x0]
    cmp	x9, x11
    cset	w12, ne	// ne = any
    cmp	x8, x10
    cinc	w12, w12, ne	// ne = any
    cbz	w12, 5558 <__cas128+0x28>
    stlxp	w12, x9, x8, [x0]
    cbnz	w12, 5534 <__cas128+0x4>
    b	5560 <__cas128+0x30>
    stlxp	w12, x2, x3, [x0]
    cbnz	w12, 5534 <__cas128+0x4>
    cmp	x9, x11
    ccmp	x8, x10, #0x0, eq	// eq = none
    cset	w0, eq	// eq = none
    b.eq	5574 <__cas128+0x44>  // b.none
    stp	x9, x8, [x1]
    ret
*/

