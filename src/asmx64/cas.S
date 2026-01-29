.section .note.GNU-stack,"",@progbits

.text
.global cas128
cas128:
   push   %rbx
   mov    %rdx,%rbx
   mov    (%rsi),%rax
   mov    0x8(%rsi),%rdx
   lock   cmpxchg16b (%rdi)
   sete   %cl
   je     .Lsuccess;
   mov    %rax,(%rsi)
   mov    %rdx,0x8(%rsi)
.Lsuccess:
   mov    %ecx,%eax
   pop    %rbx
   ret

