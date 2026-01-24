
.global __cas128_arm64
__cas128_arm64:
    ldp     x11, x10, [x1]   
retry:
    ldaxp   x9,  x8,  [x0] 
    cmp     x9,  x11
    cset    w12, ne
    cmp     x8,  x10
    cinc    w12, w12, ne
    cbz     w12, do_store
    b       fail_writeback
do_store:
    stlxp   w12, x2,  x3,  [x0]
    cbnz    w12, retry
    cmp     x9, x11
    ccmp    x8, x10, #0, eq
    cset    w0, eq
    b.eq    1f
fail_writeback:
    stp     x9, x8, [x1]
    mov     w0, #0
1:
    ret

.global __aload128_arm64
__aload128_arm64:
    mov     x8, x0          
retry_aload:
    ldaxp   x0, x1, [x8]      
    stlxp   w9, x0, x1, [x8]  
    cbnz    w9, retry_aload        
    ret
