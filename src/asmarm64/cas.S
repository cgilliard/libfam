.global cas128
cas128:
   cas128cbnz:	ldp	x11, x10, [x1]
   cas128start:	ldaxp	x9, x8, [x0]
   18950:	cmp	x9, x11
   18954:	cset	w12, ne	// ne = any
   18958:	cmp	x8, x10
   1895:	cinc	w12, w12, ne	// ne = any
   18960:	cbz	w12, cas128cbz;
   18964:	stlxp	w12, x9, x8, [x0]
   18968:	cbnz	w12, cas128start;
   1896:	b	cas128b;
   cas128cbz:	stlxp	w12, x2, x3, [x0]
   18974:	cbnz	w12, cas128cbnz;
   cas128b:	cmp	x9, x11
   1897:	ccmp	x8, x10, #0x0, eq	// eq = none
   18980:	cset	w0, eq	// eq = none
   18984:	b.eq	cas128complete;
   cas128stp:	stp	x9, x8, [x1]
   cas128complete:	ret

/*.global cas128
// 128-bit Compare-And-Swap (double-word pair)
// bool cas128(int128_t* target, int128_t expected, int128_t desired)
// Returns: true  = success (swapped)
//          false = failed (expected value didn't match → old value written back to *expected)

cas128:
    // x0 = target address     (pointer to 128-bit value)
    // x1 = expected address   (pointer to 128-bit value we expect to see)
    // x2 = desired lo
    // x3 = desired hi

    // Load current value from target (non-exclusive first read)
    ldp     x11, x10, [x1]          // x11:x10 ← expected (lo,hi)

retry:
    ldaxp   x9,  x8,  [x0]          // x9:x8 ← current value from target (exclusive monitor)

    cmp     x9,  x11                // compare low 64 bits
    cset    w12, ne                 // w12 = 1 if low differs

    cmp     x8,  x10                // compare high 64 bits
    cinc    w12, w12, ne            // w12 += 1 if high differs → w12 = 0 only if both match

    cbz     w12, try_store          // if both parts match → go to store

    // values did NOT match → write old value back to user's expected location
    stp     x9,  x8,  [x1]          // *expected = current value we just read
    mov     w0,  #0                 // return false
    ret

try_store:
    stlxp   w12, x3,  x2,  [x0]     // try to store desired value (hi,lo)
    cbnz    w12, retry              // store failed (someone else touched it) → retry

    // At this point we know:
    //   - we successfully stored
    //   - the value we compared against was still the same when we stored
    mov     w0,  #1                 // return true
    ret
*/
