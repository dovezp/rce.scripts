#!/usr/bin/python

"""
brief:          Oreans - API Unwrapper (>= 3.0.0.0 && <= 3.0.8.0)
author:         dovezp
contact:        https://github.com/dovezp
version:        2020/MAY/27
license:        Apache License 2.0 (Apache-2.0)
"""

try:
    import time
    import ctypes
    from x64dbgpy import *
    from x64dbgpy.pluginsdk import *
except ImportError as e:
    raise Exception("ERROR.ImportError: " + e.message)
except Exception as e:
    raise Exception("ERROR.UnhandledImportError: " + e.message)


# --------------------------------------------------------------------------------------------------
# GLOBAL


SCRIPT_VERSION = "2020/MAY/28"
SCRIPT_NAME = "Oreans - API Unwrapper"
SCRIPT_DESCRIPTION = "This is import resolver built for Themida 3.0.8.0's API Wrapping. Use only after stopping on the REAL OEP."
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
# IAT Entry Fetcher


class ImportEntryFetcher(object):
    def __init__(self, iat_base, iat_size):
        self.iat_entries = []
        self.iat_fixes = []
        self.iat_possible_obfuscation_count = 0
        self.__find_entries(iat_base, iat_size)
    def __find_entries(self, iat_base, iat_size):
        for i in range(iat_base, iat_base + iat_size + 4, 4):
            possible_jump = False
            jump_signature = pluginsdk.ReadDword(i) # pluginsdk.ReadDword(pluginsdk.ReadDword(i))
            if 0x0 < jump_signature <= 0xFFFF:
                print(hex(i) + ": " + hex(jump_signature))
                self.iat_possible_obfuscation_count += 1
                self.iat_entries.append({"iat": i, "value": pluginsdk.ReadDword(i)})

    def __esp_watch(self):
        for i in range(0, len(self.iat_entries)):
            if pluginsdk.x64dbg.ReadDword(pluginsdk.register.GetESP()) == self.iat_entries[i]["value"]:
                print("found possible esp accessor!")
                return True
        return False

    def __eip_monitor(self):
        if pluginsdk.register.GetCIP() == 0x4DF437:
            print("hit the magic!")
            pluginsdk.Stop()

    def __step_esp_monitor(self):
        self.__eip_monitor()
        if pluginsdk.register.GetCIP() > GetMainModuleInfo().base + GetMainModuleInfo().size:
            pluginsdk.Run()
        elif len(self.iat_entries) == 0:
            print("no more entries to monitor")
            pluginsdk.Stop()
        elif self.__esp_watch():
            print("within possible api call range keep eye out!")
            pluginsdk.StepIn()
        else:
            pluginsdk.Run()

    # 1) virtualprotect (iter 1)
    # 2) bpm 0x405000, 0, r
    # bpm 0x407000, 0, r
    def watch_dog(self):
        start = time.time()
        x64dbg.DbgCmdExecDirect("bpm " + hex(self.iat_entries[0]["iat"]) + ", 0, r")
        print("set bpm r @ " + hex(self.iat_entries[0]["iat"]))
        pluginsdk.Run()
        x64dbg.DbgCmdExecDirect("bpm " + hex(0x407000) + ", 0, r")
        print("set bpm r @ " + hex(0x407000))
        while True:
            end = time.time()
            if (end - start) > 5000:
                print("too much time on your hands")
                pluginsdk.Stop()
                break
            if pluginsdk.register.GetCIP() > GetMainModuleInfo().base + GetMainModuleInfo().size:
                pluginsdk.Run()
            if x64dbg.ReadDword(register.GetESP()) == 0x407000:
                print("mida mida")
                pluginsdk.Stop()
                break
            if pluginsdk.register.GetCIP() == 0x4DF437:
                print("hit the magic!")
                #pluginsdk.Stop()
                #break
            if len(self.iat_entries) == 0:
                print("no more entries to monitor")
                pluginsdk.Stop()
                break
            elif self.__esp_watch():
                print("within possible api call range keep eye out!")
                pluginsdk.StepIn()
                break
            else:
                print("nothing else to do but continue...")
                x64dbg.DbgCmdExecDirect("bpm " + hex(0x407000) + ", 0, r")
                print("set bpm r @ " + hex(0x407000))
                pluginsdk.Run()
                #break


    def entries_found(self):
        script_information("Found " + str(self.iat_possible_obfuscation_count) + " possible wrapped IAT entries")


# --------------------------------------------------------------------------------------------------
# Obfuscation Parser


CALL_JUMP_SIGNATURE = "E8 ?? ?? ?? ?? E9 ?? ?? ?? ??"
MOVE_STACK_JUMP_SIGNATURE = "89 44 24 0C E9 ?? ?? ?? ??"

x = 0x42D749
# while True:


"""
x = pluginsdk.Read(0x40480D, 0x100)
file = open("test", "wb")
file.write(x)
file.close()
"""


# --------------------------------------------------------------------------------------------------
# Script Launch


if __name__ == '__main__':
    if script_start():
        try:
            #iat_base_address = script_input_value("Input the suspected IAT base address in HEX")[1]
            #iat_size_address = script_input_value("Input the suspected IAT size in HEX")[1]
            #ief = ImportEntryFetcher(iat_base_address, iat_size_address)
            ief = ImportEntryFetcher(0x405000, 0x1C)
            ief.entries_found()
            # print(ief.iat_entries)
            ief.watch_dog()
        except Exception as e:
            raise Exception("ERROR.UnhandledException: " + e.message)