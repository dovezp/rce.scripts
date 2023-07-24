import idaapi
import idc


class AutoUnicode(idaapi.plugin_t):
    flags = 0
    comment = "Auto 'ASCII based' Unicode Creator"
    help = "Automatically Create 'ASCII based' Unicode Strings"
    wanted_name = "AutoUnicode"
    wanted_hotkey = "`" # button above tab usually

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def is_ascii(self, text):
        if isinstance(text, unicode):
            try:
                text.encode('ascii')
            except UnicodeEncodeError:
                return False
        else:
            try:
                text.decode('ascii')
            except UnicodeDecodeError:
                return False
        return True

    def run(self, arg):
        if (self.is_ascii(idc.GetString(idc.ScreenEA(), -1, idc.ASCSTR_UNICODE))):
            try:
                idaapi.make_ascii_string(idc.ScreenEA(), 0, idc.ASCSTR_UNICODE)
            except Exception as e:
                print("failed to convert: " + idc.GetString(idc.ScreenEA(), -1, idc.ASCSTR_UNICODE) + " to unicode string")

def PLUGIN_ENTRY():
    return AutoUnicode()