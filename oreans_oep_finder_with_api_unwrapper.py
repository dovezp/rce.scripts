#!/usr/bin/python

"""
brief:          Oreans - OEP Finder with API Unwrapper
author:         dovezp
contact:        https://github.com/dovezp
version:        2020/MAY/28
license:        Apache License 2.0 (Apache-2.0)
"""

try:
    from x64dbgpy import *
except ImportError as e:
    raise Exception("ERROR.ImportError: " + e.message)
except Exception as e:
    raise Exception("ERROR.UnhandledImportError: " + e.message)

# --------------------------------------------------------------------------------------------------
# GLOBAL


SCRIPT_VERSION = "2020/MAY/28"
SCRIPT_NAME = "Oreans - OEP Finder with API Unwrapper"
SCRIPT_DESCRIPTION = "This is fast unpacker script build for Themida 3.0.8.0."
SCRIPT_AUTHOR = "dovezp (https://github.com/dovezp)"


# --------------------------------------------------------------------------------------------------
# UI Helpers


def script_start():
    return pluginsdk.x64dbg.MessageYesNo(SCRIPT_NAME + "\n\n" + SCRIPT_DESCRIPTION + "\n\n- " + SCRIPT_AUTHOR)


def script_warning(text):
    return pluginsdk.x64dbg.GuiDisplayWarning(SCRIPT_NAME, text + "\n\n- " + SCRIPT_AUTHOR)


def script_information(text):
    return pluginsdk.x64dbg.Message(SCRIPT_NAME + "\n\n" + text + "\n\n- " + SCRIPT_AUTHOR)


def script_input_value(prompt_text):
    return pluginsdk.x64dbg.InputValue(prompt_text)


# --------------------------------------------------------------------------------------------------
# Script Helpers


def get_section(section_name, module=pluginsdk.GetMainModuleInfo()):
    for i in xrange(module.sectionCount):
        section = pluginsdk.SectionFromAddr(module.base, i)
        if section.name == section_name:
            return section
    return None


# --------------------------------------------------------------------------------------------------
# Oreans Entry Finder with API Unwrapper


class OreansUnpacker(object):
    def __init__(self):
        super(OreansUnpacker, self).__init__()
        self.kernel32_VirtualProtect = pluginsdk.x64dbg.RemoteGetProcAddress("KernelBase.dll", "VirtualProtect")

        self.module_base = pluginsdk.GetMainModuleInfo().base
        self.module_end = self.module_base + pluginsdk.GetMainModuleInfo().size

        if get_section(".text") is not None:
            # For newer configurations / others protected a "certain" way
            self.module_text_section = get_section(".text")
            # import tables are commonly stored here
            self.module_rdata_section = get_section(".rdata")
            self.module_themida_section = get_section(".themida")
        else:
            # For most common configurations that have "    " as their name
            self.module_text_section = pluginsdk.SectionFromAddr(self.module_base, 0)
            # assume following segment has possible imports (WARNING MAY BREAK!)
            self.module_rdata_section = pluginsdk.SectionFromAddr(self.module_base, 1)
            # assume following segment has possible themida (WARNING MAY BREAK!)
            self.module_themida_section = pluginsdk.SectionFromAddr(self.module_base, 2)

        self.module_text_section_end = self.module_text_section.addr + self.module_text_section.size
        self.module_rdata_section_end = self.module_rdata_section.addr + self.module_rdata_section.size
        self.module_themida_section_end = self.module_themida_section.addr + self.module_themida_section.size
        self.iat_values = self.find_iat()
        print("------------------------")
        print("targeted imports:")
        print(self.iat_values)
        print("------------------------")
        self.iat_fixes = []

    def find_iat(self):
        # Assuming module_rdata_section base is iat base
        iat_start = self.module_rdata_section.addr
        iat_possible = []
        flag_values_small = True
        while flag_values_small and iat_start < self.module_rdata_section_end:
            value_stored = pluginsdk.ReadDword(iat_start)
            if value_stored == 0:
                # Possible padding break for imports
                iat_start += 4
                pass
            elif value_stored <= 0xFFFF:
                iat_possible.append({"address": iat_start, "value": value_stored})
                iat_start += 4
            else:
                # At unusable section
                flag_values_small = False
        return iat_possible

    def __push_monitor(self):
        pluginsdk.Find
        pluginsdk.FindMem(self.module_themida_section.size, self.module_themida_section.size, "9C")

    def __step_cip_monitor(self):
        pluginsdk.SetBreakpoint(self.kernel32_VirtualProtect)
        if pluginsdk.GetCIP() != self.kernel32_VirtualProtect:
            pluginsdk.StepOut()
        pluginsdk.DeleteBreakpoint(self.kernel32_VirtualProtect)
        return

    def __step_esp_monitor(self):
        if len(self.iat_values) == 0:
            pluginsdk.Run()
        elif self.module_themida_section.addr <= pluginsdk.x64dbg.GetCIP() <= self.module_themida_section_end:
            if pluginsdk.x64dbg.ReadByte(pluginsdk.x64dbg.GetCIP()) == 0x9C:
                # 'MAGIC' VM'D PUSHFD START!
                for i in range(0, len(self.iat_values)):
                    if pluginsdk.x64dbg.ReadDword(pluginsdk.register.GetESP()) == self.iat_values[i]["value"]:
                        print("found possible import! scanning registers for api address!")
                        self.iat_fixes.append({"address": self.iat_values[i]["address"], "value": pluginsdk.register.GetEDI()})
                        del self.iat_values[i]
                        break
            else:
                pluginsdk.StepOver()
        else:
            pluginsdk.StepOut()

    def __step_stack_monitor(self):
        while True:
            self.__step_esp_monitor()
            self.__step_cip_monitor()
            if pluginsdk.x64dbg.ReadDword(pluginsdk.register.GetESP() + 4) == self.module_base:
                print(self.iat_values)
                break
            else:
                pluginsdk.StepOver()

        pluginsdk.x64dbg.DbgCmdExecDirect("bpm " + hex(self.module_text_section.addr) + ", 0, x")
        pluginsdk.Run()
        return pluginsdk.GetCIP()

    def find(self):
        entry_address = hex(self.__step_stack_monitor())
        if (entry_address != hex(0)) and (entry_address != hex(0xFFFFFFFF)) and \
                (entry_address >= hex(self.module_base)) and (entry_address <= hex(self.module_end)):
            return entry_address

        script_warning("OH NO! The script has failed!\n\n" + \
                       "First, make sure no other extra breakpoints are being used and try again!\n" + \
                       "Second, if the CIP is outside of the target module's address range try continue to run. \n" + \
                       "Third, please send me any information regarding the targeted Oreans Protector! \n" + \
                       "Example:\n" + \
                       "Version (3.0.8.0), " + \
                       "Protector Name (Themida), " + \
                       "Protection Features (Anti-Debugger Detection, Advanced API-Wrapping)," + \
                       "Target Type (DLL).")
        return -1

    def run(self):
        possible_entry = self.find()
        if possible_entry == -1:
            return
        elif (possible_entry >= hex(self.module_text_section.addr)) and \
                (possible_entry <= hex(self.module_text_section_end)):
            script_information("REAL OEP Found @ " + possible_entry + "")
        else:
            script_warning("POSSIBLE OEP Found Near @ " + possible_entry + "\n" + \
                           "If you are using a DEMO Oreans product then dismiss the splash screen. " + \
                           "It will break on the correct address.")


# --------------------------------------------------------------------------------------------------
# Script Launch


if __name__ == '__main__':
    if script_start():
        oef = OreansUnpacker()
        oef.run()
