from idaapi import * 
import idautils
import idc
import sys 

class JMPJMP:
    def __init__(self):
        self.ea = ScreenEA()
        self.errorStatus = 'Good'
        self.funcStartAddr = GetFunctionAttr(self.ea, FUNCATTR_START)
        self.checkFunctionStart()
        self.buffer = []
        self.count = 0
        self.condJmps = ['jo', 'jno', 'jb', 'jnae', 'jc', 'jnb', 'jae', 'jnc', 'jz', \
                                'je', 'jnz', 'jne', 'jbe', 'jna', 'jnbe', 'ja', 'js', 'jns', \
                                'jp', 'jpe', 'jnp', 'jpo', 'jl', 'jnge', 'jnl', 'jge', 'jle', \
                                'jng', 'jnle', 'jg']
        self.condJmpsAddr = set([])
        self.retn = ['retn', 'ret', 'retf']
        self.callAddr = set([])
        self.call = 'call' 
        self.callByte = 0xe8
        self.jmp = 'jmp'
        self.visitedAddr = set([])
        self.target = set([])
    
    def getJmpAddress(self, addr):
        "returns the address the JMP instruction jumps to"
        return GetOperandValue(addr, 0)
        
    def checkFunctionStart(self):
        'checks if the address is valid'
        if self.funcStartAddr is BADADDR:
            print "Could not find find function start address"
            self.errorStatus = 'Bad!'
            
    def checkAddr(self,addr):
        'checks if the address is valid'
        if addr is BADADDR:
            print "Could not find find function start address"
            self.errorStatus = 'Bad!'

    def getNext(self, addr):
        "returns the next address and instructions"
        next = NextHead(addr)
        return next, GetDisasm(next), GetMnem(next), Byte(addr)
        
    def getCur(self, addr):
        "returns address, dissasembly, the mnemoic and byte"
        return addr, GetDisasm(addr), GetMnem(addr), Byte(addr)
        
    def formatLine(self,addr):
        'format the line to mimic IDA layout' 
        return   idaapi.COLSTR(SegName(addr) + ':' + '%08X' % addr, idaapi.SCOLOR_INSN) + '\t' + idaapi.COLSTR(GetDisasm(addr) , idaapi.SCOLOR_INSN)
        
    def printBuffer(self):
        'print the buffer that contains the instructions minus jmps'
        v = idaapi.simplecustviewer_t()
        if v.Create("JMP CleanUp Viewer"):
            for instru in self.buffer:
                v.AddLine(instru)
            v.Show()
        else:
            print "Failed to create viewer, wa waa waaaaa"
        
    def simplify(self, addr, target = list([]) ):
        # check if valid addresss
        if addr in self.visitedAddr:
            return
        else:
            current_addr, current_inst, current_mnem, byte = self.getCur(addr)
            temp = current_addr
            self.buffer.append('__start: %s' % hex(temp))
            while(1):
                self.checkAddr(current_addr)
                if self.errorStatus != 'Good':
                    return    
                if current_mnem in self.jmp:
                    # uncomment if you want to see the jmp instruction in the output 
                    #self.buffer.append(self.formatLine(current_addr))
                    jmpAddr = self.getJmpAddress(current_addr)
                    self.visitedAddr.add(current_addr)    
                    current_addr, current_inst, current_mnem, byte = self.getCur(jmpAddr)
                    continue
                # check for conditonal jmps, if so add to the target aka come back to list
                elif current_mnem in self.condJmps:
                    self.buffer.append(self.formatLine(current_addr))
                    jmpAddr = self.getJmpAddress(current_addr)
                    target.append(jmpAddr)
                # if call, we will need the call address
                elif current_mnem in self.call and byte == self.callByte:
                    self.buffer.append(self.formatLine(current_addr))
                    target.append(GetOperandValue(current_addr,0))                
                else:
                    self.buffer.append(self.formatLine(current_addr))
                
                if current_mnem in self.retn or current_addr in self.visitedAddr:
                    break
                self.visitedAddr.add(current_addr)
                current_addr, current_inst, current_mnem, byte = self.getNext(current_addr)
            
            self.buffer.append('__end: %s ' % hex(temp))
            self.buffer.append('')
            for revisit in target:
                if revisit in self.visitedAddr:
                    continue
                else:
                    self.simplify(revisit, target)
                    
        return

def main():
    simp = JMPJMP()
    simp.simplify(GetFunctionAttr(ScreenEA(), FUNCATTR_START))
    simp.printBuffer()


if __name__ == "__main__":
    main()
