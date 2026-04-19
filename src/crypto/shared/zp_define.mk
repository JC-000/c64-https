# =============================================================================
# zp_define.mk - Canonical ca65 --asm-define flag set for the crypto ZP map
#
# Shared by c64-https in-tree builds (Makefile can include this if any source
# assembles sibling-lib .s files directly) and by each sibling lib's
# `libs/<lib>/build.sh` wrapper (Phase C.1-.3). Keeps the canonical ZP
# addresses DRY — change a ZP location in `zp_canon.inc` and update here
# in lock-step.
#
# Usage (sibling lib build.sh):
#   include $(C64_HTTPS)/src/crypto/shared/zp_define.mk
#   ca65 $(CRYPTO_ZP_DEFINES) -o foo.o foo.s
#
# The $$ in each flag is literal `$` passed through to the shell that will
# then read `$02` etc. as a hex literal for ca65 (ca65 accepts `$NN` on the
# command line via --asm-define when wrapped correctly by the invoking
# shell).
# =============================================================================

CRYPTO_ZP_DEFINES := \
    --asm-define zp_tmp1=\$$02 \
    --asm-define zp_tmp2=\$$03 \
    --asm-define w32_src1=\$$04 \
    --asm-define w32_src2=\$$06 \
    --asm-define w32_dst=\$$08 \
    --asm-define sha_temp1=\$$0a \
    --asm-define sha_temp2=\$$0e \
    --asm-define sha256_round=\$$12 \
    --asm-define cc20_round=\$$14 \
    --asm-define cc20_qr_idx=\$$15 \
    --asm-define cc20_data_ptr=\$$16 \
    --asm-define cc20_remain=\$$18 \
    --asm-define cc20_buf_pos=\$$19 \
    --asm-define lmul0=\$$14 \
    --asm-define lmul1=\$$16 \
    --asm-define poly_i=\$$1a \
    --asm-define poly_j=\$$1b \
    --asm-define poly_carry=\$$1c \
    --asm-define poly_tmp=\$$1d \
    --asm-define tls_rec_ptr=\$$1e \
    --asm-define tls_rec_idx=\$$20 \
    --asm-define tls_direction=\$$21 \
    --asm-define fp_src1=\$$22 \
    --asm-define fp_src2=\$$24 \
    --asm-define fp_dst=\$$26 \
    --asm-define fp_misc=\$$28 \
    --asm-define fp_carry=\$$2a \
    --asm-define fp_loop=\$$2b \
    --asm-define fp_mul_i=\$$39 \
    --asm-define fp_mul_j=\$$3a \
    --asm-define ec_scalar_ptr=\$$3b \
    --asm-define fe_src1=\$$2c \
    --asm-define fe_src2=\$$2e \
    --asm-define fe_dst=\$$30 \
    --asm-define fe_carry=\$$32 \
    --asm-define fe_loop=\$$33 \
    --asm-define fe_mul_i=\$$34 \
    --asm-define fe_mul_j=\$$35 \
    --asm-define x25_prev_bit=\$$38 \
    --asm-define x25_byte_idx=\$$39 \
    --asm-define x25_bit_mask=\$$3a
