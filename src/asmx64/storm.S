.section .note.GNU-stack,"",@progbits

.text
.global storm_next_block_avx2_vaes
storm_next_block_avx2_vaes:
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

.global storm_next_block_avx2_aes
storm_next_block_avx2_aes:
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

