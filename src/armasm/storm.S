.global storm_next_block_neon
storm_next_block_neon:
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

