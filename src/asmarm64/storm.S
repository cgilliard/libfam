
#ifndef NO_VECTOR
.global storm_next_block
storm_next_block:
    ldp	q0, q3, [x1]
    ldp	q1, q2, [x0]
    eor	v4.16b, v0.16b, v1.16b
    eor	v5.16b, v3.16b, v2.16b
    aese	v1.16b, v0.16b
    aesmc	v1.16b, v1.16b
    aese	v2.16b, v3.16b
    aesmc	v2.16b, v2.16b
    stp	q4, q5, [x1]
    ldp	q0, q3, [x0, #32]
    eor	v4.16b, v1.16b, v0.16b
    eor	v5.16b, v2.16b, v3.16b
    aese	v1.16b, v0.16b
    aesmc	v1.16b, v1.16b
    aese	v2.16b, v3.16b
    aesmc	v2.16b, v2.16b
    eor	v6.16b, v5.16b, v4.16b
    stp	q5, q6, [x0]
    stp	q4, q5, [x1]
    ldp	q0, q3, [x0, #64]
    eor	v0.16b, v1.16b, v0.16b
    eor	v1.16b, v2.16b, v3.16b
    stp	q0, q1, [x1]
    ldp	q2, q3, [x0]
    eor	v4.16b, v2.16b, v0.16b
    eor	v5.16b, v3.16b, v1.16b
    aese	v2.16b, v0.16b
    aesmc	v2.16b, v2.16b
    aese	v3.16b, v1.16b
    aesmc	v3.16b, v3.16b
    stp	q4, q5, [x1]
    ldp	q0, q1, [x0, #96]
    eor	v4.16b, v2.16b, v0.16b
    eor	v5.16b, v3.16b, v1.16b
    aese	v2.16b, v0.16b
    aesmc	v2.16b, v2.16b
    aese	v3.16b, v1.16b
    aesmc	v3.16b, v3.16b
    stp	q4, q5, [x1]
    ldp	q0, q1, [x0, #128]
    eor	v0.16b, v2.16b, v0.16b
    eor	v1.16b, v3.16b, v1.16b
    stp	q0, q1, [x1]
    ret

.global storm_xcrypt_buffer
storm_xcrypt_buffer:
    ldp	q2, q3, [x0]
    mov w8, #0x1      
    ldp	q1, q0, [x0, #160]
    ldp	q4, q5, [x0, #32]
    aese	v2.16b, v1.16b
    aesmc	v2.16b, v2.16b
    aese	v3.16b, v0.16b
    aesmc	v3.16b, v3.16b
    eor	v6.16b, v4.16b, v2.16b
    aese	v2.16b, v4.16b
    aesmc	v2.16b, v2.16b
    eor	v7.16b, v5.16b, v3.16b
    aese	v3.16b, v5.16b
    aesmc	v3.16b, v3.16b
    ldp	q4, q5, [x0, #64]
    eor	v2.16b, v2.16b, v4.16b
    eor	v4.16b, v6.16b, v7.16b
    eor	v3.16b, v3.16b, v5.16b
    aese	v2.16b, v7.16b
    aesmc	v2.16b, v2.16b
    aese	v3.16b, v4.16b
    aesmc	v3.16b, v3.16b
    ldp	q4, q5, [x0, #96]
    eor	v6.16b, v4.16b, v2.16b
    eor	v7.16b, v5.16b, v3.16b
    aese	v2.16b, v4.16b
    aesmc	v2.16b, v2.16b
    aese	v3.16b, v5.16b
    aesmc	v3.16b, v3.16b
    eor	v6.16b, v6.16b, v7.16b
    stp	q7, q6, [x0]
    ldp	q7, q16, [x0, #128]
    ldp	q6, q17, [x1]
    eor	v4.16b, v7.16b, v6.16b
    eor	v5.16b, v16.16b, v17.16b
    dup	v6.2d, x8
    eor	v2.16b, v2.16b, v4.16b
    eor	v3.16b, v3.16b, v5.16b
    add	v1.2d, v1.2d, v6.2d
    add	v0.2d, v0.2d, v6.2d
    stp	q2, q3, [x1]
    stp	q1, q0, [x0, #160]
    ret
#endif /* !NO_VECTOR */
