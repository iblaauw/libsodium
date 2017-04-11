# Macros and functions used by both encrypt and decrypt.

.text

# Compute one AES round key.
#
# in  RCON   = round constant immediate
#     DEST   = register to store the (possibly inverse) key
#     INV    = if 1, use the AESIMC instruction to compute
#              a key for the Equivalent Inverse Cipher
#
#     %xmm0  = previous round key, non-inverse
#              (initially, user key)
#     %xmm2  = first word is 0
#
# out DEST  <- round key
#     %xmm0 <- round key, non-inverse
#     %xmm2 <- first word is still 0
.macro key_expand RCON DEST INV=0
    aeskeygenassist \RCON, %xmm0, %xmm1
    call key_combine
.if \INV
    aesimc %xmm0, \DEST
.else
    movaps %xmm0, \DEST
.endif
.endm

# XOR together previous round key bytes and the output of
# AESKEYGENASSIST to get a new round key.
#
# in  %xmm0  = previous round key, non-inverse
#     %xmm1  = AESKEYGENASSIST result
#     %xmm2  = first word is 0
#
# out %xmm0 <- round key
#     %xmm2 <- first word is still 0
key_combine:

    # Initial state, in groups of four 32-bit words:
    #
    #   %xmm0 = P0 P1 P2 P3
    #   %xmm2 = 0  ?  ?  ?
    #   %xmm1 = ?  ?  ?  V  where
    #       V = RotWord(SubWord(P3)) xor RCON
    #
    # We want to compute a new round key K where
    #
    #   K0  =  V  xor P0
    #   K1  =  K0 xor P1  =  V xor P0 xor P1
    #   K2  =  K1 xor P2  =  V xor P0 xor P1 xor P2
    #   K3  =  K2 xor P3  =  V xor P0 xor P1 xor P2 xor P3
    #
    # You can find a good illustration of the key schedule at [1],
    # starting on slide 14.
    #
    # The exact sequence of instructions used to compute K is based
    # on clever code [2] from Linux.
    #
    # [1] http://www.formaestudio.com/rijndaelinspector/archivos/rijndaelanimation.html
    # [2] http://lxr.linux.no/linux+v3.7.4/arch/x86/crypto/aesni-intel_asm.S#L1707

    pshufd $0b11111111, %xmm1, %xmm1
    # %xmm1 = V      V      V      V

    shufps $0b00010000, %xmm0, %xmm2
    # %xmm2 = 0      0      P1     P0

    pxor   %xmm2, %xmm0
    # %xmm0 = P0     P1     P2^P1  P3^P0

    shufps $0b10001100, %xmm0, %xmm2
    # %xmm2 = 0      P0     P0     P2^P1

    pxor   %xmm2, %xmm0
    # %xmm0 = P0     P1^P0  P2^P1  P3^P2
    #                        ^P0    ^P1^P0

    pxor   %xmm1, %xmm0
    # %xmm0 = P0^V   P1^P0  P2^P1  P3^P2
    #                 ^V     ^P0^V  ^P1^P0^V

    ret

# vim: ft=asm
