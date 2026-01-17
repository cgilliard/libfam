.section .note.GNU-stack,"",@progbits

#ifndef NO_VECTOR
.text
#ifdef __VAES__
.global storm_next_block
storm_next_block:
    vmovdqa (%rdi),%ymm0
    vpxor  (%rsi),%ymm0,%ymm0
    vaesenc 0x20(%rdi),%ymm0,%ymm0
    vextracti128 $0x1,%ymm0,%xmm1
    vpxor  %xmm1,%xmm0,%xmm2
    vinserti128 $0x1,%xmm2,%ymm1,%ymm1
    vmovdqa %ymm1,(%rdi)
    vaesenc 0x40(%rdi),%ymm0,%ymm0
    vpxor  %ymm0,%ymm1,%ymm0
    vaesenc 0x60(%rdi),%ymm0,%ymm0
    vaesenc 0x80(%rdi),%ymm0,%ymm0
    vmovdqa %ymm0,(%rsi)
    vzeroupper
    ret
    cs nopw 0x0(%rax,%rax,1)
    nopl   (%rax)

.global storm_xcrypt_buffer
storm_xcrypt_buffer:
    vmovdqa (%rdi),%ymm0
    vpxor  0xa0(%rdi),%ymm0,%ymm0
    vaesenc 0x20(%rdi),%ymm0,%ymm0
    vextracti128 $0x1,%ymm0,%xmm1
    vpxor  %xmm1,%xmm0,%xmm2
    vinserti128 $0x1,%xmm2,%ymm1,%ymm1
    vmovdqa %ymm1,(%rdi)
    vaesenc 0x40(%rdi),%ymm0,%ymm0
    vpxor  %ymm0,%ymm1,%ymm0
    vaesenc 0x60(%rdi),%ymm0,%ymm0
    vaesenc 0x80(%rdi),%ymm0,%ymm0
    vpxor  (%rsi),%ymm0,%ymm0
    vmovdqa %ymm0,(%rsi)
    vmovdqa 0xa0(%rdi),%ymm0
    vpcmpeqd %ymm1,%ymm1,%ymm1
    vpsubq %ymm1,%ymm0,%ymm0
    vmovdqa %ymm0,0xa0(%rdi)
    vzeroupper
    ret
    cs nopw 0x0(%rax,%rax,1)
    nopl (%rax)

#else
.global storm_next_block
storm_next_block:
    vmovdqa (%rdi),%ymm0
    vpxor  (%rsi),%ymm0,%ymm0
    vextracti128 $0x1,%ymm0,%xmm1
    vaesenc 0x20(%rdi),%xmm0,%xmm0
    vaesenc 0x30(%rdi),%xmm1,%xmm1
    vpxor  %xmm0,%xmm1,%xmm2
    vmovdqa %xmm1,(%rdi)
    vmovdqa %xmm2,0x10(%rdi)
    vaesenc 0x40(%rdi),%xmm0,%xmm0
    vaesenc 0x50(%rdi),%xmm1,%xmm3
    vpxor  %xmm1,%xmm0,%xmm0
    vpxor  %xmm2,%xmm3,%xmm1
    vaesenc 0x60(%rdi),%xmm0,%xmm0
    vaesenc 0x70(%rdi),%xmm1,%xmm1
    vaesenc 0x80(%rdi),%xmm0,%xmm0
    vaesenc 0x90(%rdi),%xmm1,%xmm1
    vmovdqa %xmm0,(%rsi)
    vmovdqa %xmm1,0x10(%rsi)
    vzeroupper
    ret
    cs nopw 0x0(%rax,%rax,1)

.global storm_xcrypt_buffer
storm_xcrypt_buffer:
    vmovdqa (%rdi),%ymm0
    vpxor  0xa0(%rdi),%ymm0,%ymm0
    vextracti128 $0x1,%ymm0,%xmm1
    vaesenc 0x20(%rdi),%xmm0,%xmm0
    vaesenc 0x30(%rdi),%xmm1,%xmm1
    vpxor  %xmm0,%xmm1,%xmm2
    vmovdqa %xmm1,(%rdi)
    vmovdqa %xmm2,0x10(%rdi)
    vaesenc 0x40(%rdi),%xmm0,%xmm0
    vaesenc 0x50(%rdi),%xmm1,%xmm3
    vpxor  %xmm1,%xmm0,%xmm0
    vpxor  %xmm2,%xmm3,%xmm1
    vaesenc 0x60(%rdi),%xmm0,%xmm0
    vaesenc 0x70(%rdi),%xmm1,%xmm1
    vaesenc 0x80(%rdi),%xmm0,%xmm0
    vaesenc 0x90(%rdi),%xmm1,%xmm1
    vinserti128 $0x1,%xmm1,%ymm0,%ymm0
    vpxor  (%rsi),%ymm0,%ymm0
    vmovdqa %ymm0,(%rsi)
    vmovdqa 0xa0(%rdi),%ymm0
    vpcmpeqd %ymm1,%ymm1,%ymm1
    vpsubq %ymm1,%ymm0,%ymm0
    vmovdqa %ymm0,0xa0(%rdi)
    vzeroupper
    ret
    nopw   0x0(%rax,%rax,1)


#endif /* !__VAES__ */
#endif /* !NO_VECTOR */
