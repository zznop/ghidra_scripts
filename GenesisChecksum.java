//Fix SEGA Genesis ROM Checksum
//@author zznop
//@category Patching
//@keybinding
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;

public class GenesisChecksum extends GhidraScript {
    static final int START_OFFSET = 0x200;
    static final int CHECKSUM_OFFSET = 0x18e;
    static final int WORD_SIZE = 0x2;

    public void run() throws Exception {
        Memory memory = currentProgram.getMemory();
        Address currAddr = currentProgram.getMinAddress().add(START_OFFSET);
        Address checksumAddr = currentProgram.getMinAddress().add(CHECKSUM_OFFSET);
        long maxSize = currentProgram.getMaxAddress().getOffset() + 1; // EOF
        short checksum = 0;
        long currIndex = currAddr.getOffset();

        for (; currIndex <= maxSize-WORD_SIZE; currIndex += WORD_SIZE) {
            checksum = (short)((checksum + memory.getShort(currAddr)) & 0x0000ffff);
            currAddr = currAddr.add(WORD_SIZE);
        }

        memory.setShort(checksumAddr, checksum);
        println("ROM checksum calculated (and fixed): 0x" + Integer.toHexString(checksum & 0x0000ffff));
    }

}
