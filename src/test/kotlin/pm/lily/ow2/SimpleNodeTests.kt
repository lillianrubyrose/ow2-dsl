package pm.lily.ow2

import org.objectweb.asm.Opcodes
import kotlin.test.Test

class SimpleNodeTests {
    @Test
    fun nop() {
        assert(insnList { nop }[0].opcode == Opcodes.NOP)
    }

    @Test
    fun aconst_null() {
        assert(insnList { aconst_null }[0].opcode == Opcodes.ACONST_NULL)
    }

    @Test
    fun iconst_m1() {
        assert(insnList { iconst_m1 }[0].opcode == Opcodes.ICONST_M1)
    }

    @Test
    fun iconst_0() {
        assert(insnList { iconst_0 }[0].opcode == Opcodes.ICONST_0)
    }

    @Test
    fun iconst_1() {
        assert(insnList { iconst_1 }[0].opcode == Opcodes.ICONST_1)
    }

    @Test
    fun iconst_2() {
        assert(insnList { iconst_2 }[0].opcode == Opcodes.ICONST_2)
    }

    @Test
    fun iconst_3() {
        assert(insnList { iconst_3 }[0].opcode == Opcodes.ICONST_3)
    }

    @Test
    fun iconst_4() {
        assert(insnList { iconst_4 }[0].opcode == Opcodes.ICONST_4)
    }

    @Test
    fun iconst_5() {
        assert(insnList { iconst_5 }[0].opcode == Opcodes.ICONST_5)
    }

    @Test
    fun lconst_0() {
        assert(insnList { lconst_0 }[0].opcode == Opcodes.LCONST_0)
    }

    @Test
    fun lconst_1() {
        assert(insnList { lconst_1 }[0].opcode == Opcodes.LCONST_1)
    }

    @Test
    fun fconst_0() {
        assert(insnList { fconst_0 }[0].opcode == Opcodes.FCONST_0)
    }

    @Test
    fun fconst_1() {
        assert(insnList { fconst_1 }[0].opcode == Opcodes.FCONST_1)
    }

    @Test
    fun fconst_2() {
        assert(insnList { fconst_2 }[0].opcode == Opcodes.FCONST_2)
    }

    @Test
    fun dconst_0() {
        assert(insnList { dconst_0 }[0].opcode == Opcodes.DCONST_0)
    }

    @Test
    fun dconst_1() {
        assert(insnList { dconst_1 }[0].opcode == Opcodes.DCONST_1)
    }

    @Test
    fun bipush() {
        assert(insnList { bipush }[0].opcode == Opcodes.BIPUSH)
    }

    @Test
    fun sipush() {
        assert(insnList { sipush }[0].opcode == Opcodes.SIPUSH)
    }

    @Test
    fun ldc() {
        assert(insnList { ldc }[0].opcode == Opcodes.LDC)
    }

    @Test
    fun iload() {
        assert(insnList { iload }[0].opcode == Opcodes.ILOAD)
    }

    @Test
    fun lload() {
        assert(insnList { lload }[0].opcode == Opcodes.LLOAD)
    }

    @Test
    fun fload() {
        assert(insnList { fload }[0].opcode == Opcodes.FLOAD)
    }

    @Test
    fun dload() {
        assert(insnList { dload }[0].opcode == Opcodes.DLOAD)
    }

    @Test
    fun aload() {
        assert(insnList { aload }[0].opcode == Opcodes.ALOAD)
    }

    @Test
    fun iaload() {
        assert(insnList { iaload }[0].opcode == Opcodes.IALOAD)
    }

    @Test
    fun laload() {
        assert(insnList { laload }[0].opcode == Opcodes.LALOAD)
    }

    @Test
    fun faload() {
        assert(insnList { faload }[0].opcode == Opcodes.FALOAD)
    }

    @Test
    fun daload() {
        assert(insnList { daload }[0].opcode == Opcodes.DALOAD)
    }

    @Test
    fun aaload() {
        assert(insnList { aaload }[0].opcode == Opcodes.AALOAD)
    }

    @Test
    fun baload() {
        assert(insnList { baload }[0].opcode == Opcodes.BALOAD)
    }

    @Test
    fun caload() {
        assert(insnList { caload }[0].opcode == Opcodes.CALOAD)
    }

    @Test
    fun saload() {
        assert(insnList { saload }[0].opcode == Opcodes.SALOAD)
    }

    @Test
    fun istore() {
        assert(insnList { istore }[0].opcode == Opcodes.ISTORE)
    }

    @Test
    fun lstore() {
        assert(insnList { lstore }[0].opcode == Opcodes.LSTORE)
    }

    @Test
    fun fstore() {
        assert(insnList { fstore }[0].opcode == Opcodes.FSTORE)
    }

    @Test
    fun dstore() {
        assert(insnList { dstore }[0].opcode == Opcodes.DSTORE)
    }

    @Test
    fun astore() {
        assert(insnList { astore }[0].opcode == Opcodes.ASTORE)
    }

    @Test
    fun iastore() {
        assert(insnList { iastore }[0].opcode == Opcodes.IASTORE)
    }

    @Test
    fun lastore() {
        assert(insnList { lastore }[0].opcode == Opcodes.LASTORE)
    }

    @Test
    fun fastore() {
        assert(insnList { fastore }[0].opcode == Opcodes.FASTORE)
    }

    @Test
    fun dastore() {
        assert(insnList { dastore }[0].opcode == Opcodes.DASTORE)
    }

    @Test
    fun aastore() {
        assert(insnList { aastore }[0].opcode == Opcodes.AASTORE)
    }

    @Test
    fun bastore() {
        assert(insnList { bastore }[0].opcode == Opcodes.BASTORE)
    }

    @Test
    fun castore() {
        assert(insnList { castore }[0].opcode == Opcodes.CASTORE)
    }

    @Test
    fun sastore() {
        assert(insnList { sastore }[0].opcode == Opcodes.SASTORE)
    }

    @Test
    fun pop() {
        assert(insnList { pop }[0].opcode == Opcodes.POP)
    }

    @Test
    fun pop2() {
        assert(insnList { pop2 }[0].opcode == Opcodes.POP2)
    }

    @Test
    fun dup() {
        assert(insnList { dup }[0].opcode == Opcodes.DUP)
    }

    @Test
    fun dup_x1() {
        assert(insnList { dup_x1 }[0].opcode == Opcodes.DUP_X1)
    }

    @Test
    fun dup_x2() {
        assert(insnList { dup_x2 }[0].opcode == Opcodes.DUP_X2)
    }

    @Test
    fun dup2() {
        assert(insnList { dup2 }[0].opcode == Opcodes.DUP2)
    }

    @Test
    fun dup2_x1() {
        assert(insnList { dup2_x1 }[0].opcode == Opcodes.DUP2_X1)
    }

    @Test
    fun dup2_x2() {
        assert(insnList { dup2_x2 }[0].opcode == Opcodes.DUP2_X2)
    }

    @Test
    fun swap() {
        assert(insnList { swap }[0].opcode == Opcodes.SWAP)
    }

    @Test
    fun iadd() {
        assert(insnList { iadd }[0].opcode == Opcodes.IADD)
    }

    @Test
    fun ladd() {
        assert(insnList { ladd }[0].opcode == Opcodes.LADD)
    }

    @Test
    fun fadd() {
        assert(insnList { fadd }[0].opcode == Opcodes.FADD)
    }

    @Test
    fun dadd() {
        assert(insnList { dadd }[0].opcode == Opcodes.DADD)
    }

    @Test
    fun isub() {
        assert(insnList { isub }[0].opcode == Opcodes.ISUB)
    }

    @Test
    fun lsub() {
        assert(insnList { lsub }[0].opcode == Opcodes.LSUB)
    }

    @Test
    fun fsub() {
        assert(insnList { fsub }[0].opcode == Opcodes.FSUB)
    }

    @Test
    fun dsub() {
        assert(insnList { dsub }[0].opcode == Opcodes.DSUB)
    }

    @Test
    fun imul() {
        assert(insnList { imul }[0].opcode == Opcodes.IMUL)
    }

    @Test
    fun lmul() {
        assert(insnList { lmul }[0].opcode == Opcodes.LMUL)
    }

    @Test
    fun fmul() {
        assert(insnList { fmul }[0].opcode == Opcodes.FMUL)
    }

    @Test
    fun dmul() {
        assert(insnList { dmul }[0].opcode == Opcodes.DMUL)
    }

    @Test
    fun idiv() {
        assert(insnList { idiv }[0].opcode == Opcodes.IDIV)
    }

    @Test
    fun ldiv() {
        assert(insnList { ldiv }[0].opcode == Opcodes.LDIV)
    }

    @Test
    fun fdiv() {
        assert(insnList { fdiv }[0].opcode == Opcodes.FDIV)
    }

    @Test
    fun ddiv() {
        assert(insnList { ddiv }[0].opcode == Opcodes.DDIV)
    }

    @Test
    fun irem() {
        assert(insnList { irem }[0].opcode == Opcodes.IREM)
    }

    @Test
    fun lrem() {
        assert(insnList { lrem }[0].opcode == Opcodes.LREM)
    }

    @Test
    fun frem() {
        assert(insnList { frem }[0].opcode == Opcodes.FREM)
    }

    @Test
    fun drem() {
        assert(insnList { drem }[0].opcode == Opcodes.DREM)
    }

    @Test
    fun ineg() {
        assert(insnList { ineg }[0].opcode == Opcodes.INEG)
    }

    @Test
    fun lneg() {
        assert(insnList { lneg }[0].opcode == Opcodes.LNEG)
    }

    @Test
    fun fneg() {
        assert(insnList { fneg }[0].opcode == Opcodes.FNEG)
    }

    @Test
    fun dneg() {
        assert(insnList { dneg }[0].opcode == Opcodes.DNEG)
    }

    @Test
    fun ishl() {
        assert(insnList { ishl }[0].opcode == Opcodes.ISHL)
    }

    @Test
    fun lshl() {
        assert(insnList { lshl }[0].opcode == Opcodes.LSHL)
    }

    @Test
    fun ishr() {
        assert(insnList { ishr }[0].opcode == Opcodes.ISHR)
    }

    @Test
    fun lshr() {
        assert(insnList { lshr }[0].opcode == Opcodes.LSHR)
    }

    @Test
    fun iushr() {
        assert(insnList { iushr }[0].opcode == Opcodes.IUSHR)
    }

    @Test
    fun lushr() {
        assert(insnList { lushr }[0].opcode == Opcodes.LUSHR)
    }

    @Test
    fun iand() {
        assert(insnList { iand }[0].opcode == Opcodes.IAND)
    }

    @Test
    fun land() {
        assert(insnList { land }[0].opcode == Opcodes.LAND)
    }

    @Test
    fun ior() {
        assert(insnList { ior }[0].opcode == Opcodes.IOR)
    }

    @Test
    fun lor() {
        assert(insnList { lor }[0].opcode == Opcodes.LOR)
    }

    @Test
    fun ixor() {
        assert(insnList { ixor }[0].opcode == Opcodes.IXOR)
    }

    @Test
    fun lxor() {
        assert(insnList { lxor }[0].opcode == Opcodes.LXOR)
    }

    @Test
    fun iinc() {
        assert(insnList { iinc }[0].opcode == Opcodes.IINC)
    }

    @Test
    fun i2l() {
        assert(insnList { i2l }[0].opcode == Opcodes.I2L)
    }

    @Test
    fun i2f() {
        assert(insnList { i2f }[0].opcode == Opcodes.I2F)
    }

    @Test
    fun i2d() {
        assert(insnList { i2d }[0].opcode == Opcodes.I2D)
    }

    @Test
    fun l2i() {
        assert(insnList { l2i }[0].opcode == Opcodes.L2I)
    }

    @Test
    fun l2f() {
        assert(insnList { l2f }[0].opcode == Opcodes.L2F)
    }

    @Test
    fun l2d() {
        assert(insnList { l2d }[0].opcode == Opcodes.L2D)
    }

    @Test
    fun f2i() {
        assert(insnList { f2i }[0].opcode == Opcodes.F2I)
    }

    @Test
    fun f2l() {
        assert(insnList { f2l }[0].opcode == Opcodes.F2L)
    }

    @Test
    fun f2d() {
        assert(insnList { f2d }[0].opcode == Opcodes.F2D)
    }

    @Test
    fun d2i() {
        assert(insnList { d2i }[0].opcode == Opcodes.D2I)
    }

    @Test
    fun d2l() {
        assert(insnList { d2l }[0].opcode == Opcodes.D2L)
    }

    @Test
    fun d2f() {
        assert(insnList { d2f }[0].opcode == Opcodes.D2F)
    }

    @Test
    fun i2b() {
        assert(insnList { i2b }[0].opcode == Opcodes.I2B)
    }

    @Test
    fun i2c() {
        assert(insnList { i2c }[0].opcode == Opcodes.I2C)
    }

    @Test
    fun i2s() {
        assert(insnList { i2s }[0].opcode == Opcodes.I2S)
    }

    @Test
    fun lcmp() {
        assert(insnList { lcmp }[0].opcode == Opcodes.LCMP)
    }

    @Test
    fun fcmpl() {
        assert(insnList { fcmpl }[0].opcode == Opcodes.FCMPL)
    }

    @Test
    fun fcmpg() {
        assert(insnList { fcmpg }[0].opcode == Opcodes.FCMPG)
    }

    @Test
    fun dcmpl() {
        assert(insnList { dcmpl }[0].opcode == Opcodes.DCMPL)
    }

    @Test
    fun dcmpg() {
        assert(insnList { dcmpg }[0].opcode == Opcodes.DCMPG)
    }

    @Test
    fun ifeq() {
        assert(insnList { ifeq }[0].opcode == Opcodes.IFEQ)
    }

    @Test
    fun ifne() {
        assert(insnList { ifne }[0].opcode == Opcodes.IFNE)
    }

    @Test
    fun iflt() {
        assert(insnList { iflt }[0].opcode == Opcodes.IFLT)
    }

    @Test
    fun ifge() {
        assert(insnList { ifge }[0].opcode == Opcodes.IFGE)
    }

    @Test
    fun ifgt() {
        assert(insnList { ifgt }[0].opcode == Opcodes.IFGT)
    }

    @Test
    fun ifle() {
        assert(insnList { ifle }[0].opcode == Opcodes.IFLE)
    }

    @Test
    fun if_icmpeq() {
        assert(insnList { if_icmpeq }[0].opcode == Opcodes.IF_ICMPEQ)
    }

    @Test
    fun if_icmpne() {
        assert(insnList { if_icmpne }[0].opcode == Opcodes.IF_ICMPNE)
    }

    @Test
    fun if_icmplt() {
        assert(insnList { if_icmplt }[0].opcode == Opcodes.IF_ICMPLT)
    }

    @Test
    fun if_icmpge() {
        assert(insnList { if_icmpge }[0].opcode == Opcodes.IF_ICMPGE)
    }

    @Test
    fun if_icmpgt() {
        assert(insnList { if_icmpgt }[0].opcode == Opcodes.IF_ICMPGT)
    }

    @Test
    fun if_icmple() {
        assert(insnList { if_icmple }[0].opcode == Opcodes.IF_ICMPLE)
    }

    @Test
    fun if_acmpeq() {
        assert(insnList { if_acmpeq }[0].opcode == Opcodes.IF_ACMPEQ)
    }

    @Test
    fun if_acmpne() {
        assert(insnList { if_acmpne }[0].opcode == Opcodes.IF_ACMPNE)
    }

    @Test
    fun goto() {
        assert(insnList { goto }[0].opcode == Opcodes.GOTO)
    }

    @Test
    fun jsr() {
        assert(insnList { jsr }[0].opcode == Opcodes.JSR)
    }

    @Test
    fun ret() {
        assert(insnList { ret }[0].opcode == Opcodes.RET)
    }

    @Test
    fun tableswitch() {
        assert(insnList { tableswitch }[0].opcode == Opcodes.TABLESWITCH)
    }

    @Test
    fun lookupswitch() {
        assert(insnList { lookupswitch }[0].opcode == Opcodes.LOOKUPSWITCH)
    }

    @Test
    fun ireturn() {
        assert(insnList { ireturn }[0].opcode == Opcodes.IRETURN)
    }

    @Test
    fun lreturn() {
        assert(insnList { lreturn }[0].opcode == Opcodes.LRETURN)
    }

    @Test
    fun freturn() {
        assert(insnList { freturn }[0].opcode == Opcodes.FRETURN)
    }

    @Test
    fun dreturn() {
        assert(insnList { dreturn }[0].opcode == Opcodes.DRETURN)
    }

    @Test
    fun areturn() {
        assert(insnList { areturn }[0].opcode == Opcodes.ARETURN)
    }

    @Test
    fun return_() {
        assert(insnList { return_ }[0].opcode == Opcodes.RETURN)
    }

    @Test
    fun getstatic() {
        assert(insnList { getstatic }[0].opcode == Opcodes.GETSTATIC)
    }

    @Test
    fun putstatic() {
        assert(insnList { putstatic }[0].opcode == Opcodes.PUTSTATIC)
    }

    @Test
    fun getfield() {
        assert(insnList { getfield }[0].opcode == Opcodes.GETFIELD)
    }

    @Test
    fun putfield() {
        assert(insnList { putfield }[0].opcode == Opcodes.PUTFIELD)
    }

    @Test
    fun invokevirtual() {
        assert(insnList { invokevirtual }[0].opcode == Opcodes.INVOKEVIRTUAL)
    }

    @Test
    fun invokespecial() {
        assert(insnList { invokespecial }[0].opcode == Opcodes.INVOKESPECIAL)
    }

    @Test
    fun invokestatic() {
        assert(insnList { invokestatic }[0].opcode == Opcodes.INVOKESTATIC)
    }

    @Test
    fun invokeinterface() {
        assert(insnList { invokeinterface }[0].opcode == Opcodes.INVOKEINTERFACE)
    }

    @Test
    fun invokedynamic() {
        assert(insnList { invokedynamic }[0].opcode == Opcodes.INVOKEDYNAMIC)
    }

    @Test
    fun new() {
        assert(insnList { new }[0].opcode == Opcodes.NEW)
    }

    @Test
    fun newarray() {
        assert(insnList { newarray }[0].opcode == Opcodes.NEWARRAY)
    }

    @Test
    fun anewarray() {
        assert(insnList { anewarray }[0].opcode == Opcodes.ANEWARRAY)
    }

    @Test
    fun arraylength() {
        assert(insnList { arraylength }[0].opcode == Opcodes.ARRAYLENGTH)
    }

    @Test
    fun athrow() {
        assert(insnList { athrow }[0].opcode == Opcodes.ATHROW)
    }

    @Test
    fun checkcast() {
        assert(insnList { checkcast }[0].opcode == Opcodes.CHECKCAST)
    }

    @Test
    fun instanceof() {
        assert(insnList { instanceof }[0].opcode == Opcodes.INSTANCEOF)
    }

    @Test
    fun monitorenter() {
        assert(insnList { monitorenter }[0].opcode == Opcodes.MONITORENTER)
    }

    @Test
    fun monitorexit() {
        assert(insnList { monitorexit }[0].opcode == Opcodes.MONITOREXIT)
    }

    @Test
    fun multianewarray() {
        assert(insnList { multianewarray }[0].opcode == Opcodes.MULTIANEWARRAY)
    }

    @Test
    fun ifnull() {
        assert(insnList { ifnull }[0].opcode == Opcodes.IFNULL)
    }

    @Test
    fun ifnonnull() {
        assert(insnList { ifnonnull }[0].opcode == Opcodes.IFNONNULL)
    }
}