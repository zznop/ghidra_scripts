//Given a raw binary SEGA Genesis ROM, construct the vector table and ROM header and kickoff disassembly
//@author zznop
//@category Binary
//@keybinding
//@menupath 
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class GenesisVectorTable extends GhidraScript {
    // Constants
    private static final long VECTOR_TABLE_START = 0x4;
    private static final long VECTOR_TABLE_END   = 0x100;
    private static final long DWORD_SIZE         = 0x4;
    private static final long PTR_PROGRAM_START  = 0x4;
    private static final long PTR_HBLANK         = 0x70;
    private static final long PTR_VBLANK         = 0x78;
    private static final int VDP_DATA            = 0x00C00000;
    private static final int VDP_CONTROL         = 0x00C00004;
    private static final int VDP_COUNTER         = 0x00C00008;
    private static final int CTRL_1_DATA         = 0x00A10003;
    private static final int CTRL_1_CONTROL      = 0x00A10009;
    private static final int CTRL_2_DATA         = 0x00A10005;
    private static final int CTRL_2_CONTROL      = 0x00A1000B;
    private static final int REG_HWVERSION       = 0x00A10001;
    private static final int REG_TMS             = 0x00A14000;
    private static final int PSG_INPUT           = 0x00C00011;
    private static final int Z80_ADDRESS_SPACE   = 0x00A10000;
    private static final int Z80_BUS             = 0x00A11100;
    private static final int Z80_RESET           = 0x00A11200;

    // Members
    private Address currAddr = null;

    /**
     * Creates an ASCII string at the current address, applys a label, and
     * increments the cursor past the string
     */
    private void createLabeledStringAndIncrement(String label, int length) throws Exception {
        createAsciiString(currAddr, length);
        createLabel(currAddr, label, true);
        currAddr = currAddr.add(length);
    }

    /**
     * Creates an numerical data field at the current address and increments the
     * cursor past the field.
     */
    private void createLabeledIntegerAndIncrement(String label, DataType dataType, long length) throws Exception {
        createData(currAddr, dataType);
        createLabel(currAddr, label, true);
        currAddr = currAddr.add(length);
    }

    /**
     * Applies types and labels fields of the vector table
     */
    private void createVectorTable() throws Exception {
        createLabeledIntegerAndIncrement("PtrInitialStack",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("PtrProgramStart",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrBusError",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrAddressError",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrIllegalInstruction",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrDivisionByZero",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrChkException",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrapVException",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrPrivilegeViolation",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTraceException",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrLineAEmulator",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrLineFEmulator",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused00",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused01",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused02",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused03",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused04",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused05",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused06",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused07",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused08",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused09",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused10",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused11",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrSpuriousException",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrIrqL1",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrIrqL2",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrIrqL3",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrIrqL4",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrIrqL5",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrIrqL6",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrIrqL7",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap00",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap01",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap02",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap03",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap04",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap05",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap06",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap07",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap08",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap09",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap10",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap11",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap12",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap13",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap14",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectPtrTrap15",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused12",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused13",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused14",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused15",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused16",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused17",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused18",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused19",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused20",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused21",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused22",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused23",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused24",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused25",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused26",
            UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("VectUnused27",
            UnsignedIntegerDataType.dataType, 4);
    }

    /**
     * Applies types and labels to the ROM header
     */
    private void createRomHeader() throws Exception {
        createLabeledStringAndIncrement("ConsoleName", 16);
        createLabeledStringAndIncrement("Copyright", 16);
        createLabeledStringAndIncrement("DomesticName", 48);
        createLabeledStringAndIncrement("InternationalName", 48);
        createLabeledStringAndIncrement("SerialRevision", 14);
        createLabeledIntegerAndIncrement("Checksum", UnsignedShortDataType.dataType, 2);
        createLabeledStringAndIncrement("IoSupport", 16);
        createLabeledIntegerAndIncrement("RomStartAddress", UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("RomEndAddress", UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("RamStartAddress", UnsignedIntegerDataType.dataType, 4);
        createLabeledIntegerAndIncrement("RamEndAddress", UnsignedIntegerDataType.dataType, 4);
        createLabeledStringAndIncrement("SramInfo", 12);
        createLabeledStringAndIncrement("Notes", 52);
        createLabeledStringAndIncrement("Region", 16);
    }

    /**
     * Iterate the function pointers in the vector table and disassemble
     */
    private void disassembleExceptionHandlers() throws Exception {
        long handlerPtr = 0;
        Memory memory = currentProgram.getMemory();
        currAddr = currentProgram.getMinAddress().add(VECTOR_TABLE_START);
        for (long i = currAddr.getOffset(); i <= VECTOR_TABLE_END; i += DWORD_SIZE) {
            handlerPtr = memory.getInt(currAddr);
            disassemble(toAddr(handlerPtr));
            currAddr = currAddr.add(DWORD_SIZE);
        }
    }

    /**
     * Apply labels to important code and data addresses
     */
    private void labelImportantFields() throws Exception {
        Memory memory = currentProgram.getMemory();
        int ptr = memory.getInt(toAddr(PTR_PROGRAM_START));
        createLabel(toAddr(ptr), "ProgramStart", true);
        ptr = memory.getInt(toAddr(PTR_HBLANK));
        createLabel(toAddr(ptr), "HBlank", true);
        ptr = memory.getInt(toAddr(PTR_VBLANK));
        createLabel(toAddr(ptr), "VBlank", true);
        createLabel(toAddr(VDP_CONTROL), "VDP_CONTROL", true);
        createLabel(toAddr(VDP_COUNTER), "VDP_COUNTER", true);
        createLabel(toAddr(VDP_DATA), "VDP_DATA", true);
        createLabel(toAddr(CTRL_1_CONTROL), "CTRL_1_CONTROL", true);
        createLabel(toAddr(CTRL_1_DATA), "CTRL_1_DATA", true);
        createLabel(toAddr(CTRL_2_CONTROL), "CTRL_2_CONTROL", true);
        createLabel(toAddr(CTRL_2_DATA), "CTRL_2_DATA", true);
        createLabel(toAddr(REG_HWVERSION), "REG_HWVERSION", true);
        createLabel(toAddr(REG_TMS), "REG_TMS", true);
        createLabel(toAddr(PSG_INPUT), "PSG_INPUT", true);
        createLabel(toAddr(Z80_ADDRESS_SPACE), "Z80_ADDRESS_SPACE", true);
        createLabel(toAddr(Z80_BUS), "Z80_BUS", true);
        createLabel(toAddr(Z80_RESET), "Z80_RESET", true);
    }

    /**
     * Main
     */
    public void run() throws Exception {
        currAddr = currentProgram.getMinAddress();
        createVectorTable();
        createRomHeader();
        disassembleExceptionHandlers();
        labelImportantFields();
    }
}
