# pylint: disable=C0301,C0103,C0111
#
# License: Beerware license ;)
#
# Link update:
#   https://github.com/HongThatCong/LazyIDA
# Org:
#   https://github.com/L4ys/LazyIDA
#
# Version histories:
# 09/08/2020 - HTC (VinCSS)
#   - fix bug read_selection
#   - fix bug parse_location, so Shift-G hotkey can jumpto any ea, name possibles
#   - change "C" hotkey to Shift-C, because C is duplicate function with IDA C and Ctrl-C hotkey
#     Shift-C will copy full name of a current highlight name
#   - add "Shfit-V" hotkey, paste name from clipboard to current highlight name or current addr (fullname)
# 10/08/2020
#   - Fix bug sanitize name from clipboard text - idea of Ngon Nguyen, code by HTC
# 30/08/2020
#   - Rearrange actions and hotkeys - HTC
#   - Refactor, clean code, add nhieu tinh nang. Nhieu qua, lam bieng liet ke, chiu kho xem code hay diff :D
# 31/01/2021
#   - Release ver 1.0.5
# 20/12/2021:
#   - Add Revert IDA Decision
#
from __future__ import division
from __future__ import print_function

import os
import sys
import string
import re
import base64
import binascii

from struct import unpack

import idaapi
import idautils
import idc
import ida_kernwin
import ida_xref
import ida_name
import ida_nalt
import ida_loader

from PyQt5.Qt import QApplication

PY3 = sys.version_info >= (3, 0)

PLUGIN_NAME = "LazyIDA"

# Popup menus action names
ACTION_MENU_CONVERT = ["lazyida::convert_%d" % _i for _i in range(12)]
ACTION_MENU_SCAN_VUL = "lazyida::scan_vul"
ACTION_MENU_COPY_DATA = "lazyida::copy_data"        # added by merc
ACTION_MENU_DUMP_DATA = "lazyida::dump_data"        # HTC
ACTION_MENU_XOR_DATA = "lazyida::xor_data"          # HTC & CatBui mod
ACTION_MENU_FILL_NOP = "lazyida::fill_nop"
ACTION_MENU_NOP_HIDER = "lazyida::nop_hider"        # added by HTC
ACTION_MENU_AUTO_OFF = "lazyida::turn_off_ida_decision"
ACTION_MENU_B64STD = "lazyida::base64std_decode"
ACTION_MENU_B64URL = "lazyida::base64url_decode"

#
# HTC: change actions name and hotkeys - 30/08/2020
# Available Shift- hotkeys: B C G H J K O Q V T Y Z
# All actions name and hotkeys, enable allways
# Action is tuple: name, label, shortcut, tooltip/hint, iconid
#
ACTION_HOTKEY_COPY_EA = ("lazyida::copy_ea", "Copy EA", "Shift-Y", "Copy current EA to clipboard", 0x1F)
ACTION_HOTKEY_COPY_RVA = ("lazyida::copy_rva", "Copy RVA", "Shift-Z", "Copy current RVA to clipboard", 0x1F)
ACTION_HOTKEY_COPY_FOFS = ("lazyida::copy_fofs", "Copy File Offset", "Shift-O", "Copy current file offset to clipboard", 0x1F)
ACTION_HOTKEY_COPY_NAME = ("lazyida::copy_name", "Copy highligh name", "Shift-C", "Copy current highlight full name to clipboard", 0x1F)
ACTION_HOTKEY_PASTE_NAME = ("lazyida::paste_name", "Paste to highligh name", "Shift-V", "Change the fullname of current highlight to clipboard text", 0x13)
ACTION_HOTKEY_GOTO_CLIP = ("lazyida::goto_clip", "Goto text in clipboard", "Shift-G", "Goto current name or ea in clipboard", 0x7D)
ACTION_HOTKEY_GOTO_FOFS = ("lazyida::goto_fofs", "Goto file offset", "Shift-J", "Goto file offset", 0x7D)  # IDA already had this action "JumpFileOffset"
ACTION_HOTKEY_GOTO_RVA = ("lazyida::goto_rva", "Goto RVA", "Alt-G", "Goto RVA", 0x7D)
ACTION_HOTKEY_SEARCH_GOOGLE = ("lazyida::search_google", "Search Google", "Ctrl-Shift-G", "Search Google", 0x21)
ACTION_HOTKEY_SEARCH_MSDOC = ("lazyida::search_msdoc", "Search MS Docs", "Ctrl-Shift-R", "Search MS Docs", 0x21)
ACTION_HOTKEY_SEARCH_BING = ("lazyida::search_bing", "Search Bing", "Ctrl-Shift-J", "Search Bing", 0x21)
ACTION_HOTKEY_SEARCH_GITHUB = ("lazyida::search_github", "Search Github", "Ctrl-Shift-H", "Search Github", 0x21)
ACTION_HOTKEY_OPEN_URL = ("lazyida::open_url", "Open URL", "",  "Open URL", 0)

ALL_HOTKEY_ACTIONS = (
    ACTION_HOTKEY_COPY_EA,
    ACTION_HOTKEY_COPY_RVA,
    ACTION_HOTKEY_COPY_FOFS,
    ACTION_HOTKEY_COPY_NAME,
    ACTION_HOTKEY_PASTE_NAME,
    ACTION_HOTKEY_GOTO_CLIP,
    ACTION_HOTKEY_GOTO_FOFS,
    ACTION_HOTKEY_GOTO_RVA,
    ACTION_HOTKEY_SEARCH_GOOGLE,
    ACTION_HOTKEY_SEARCH_MSDOC,
    ACTION_HOTKEY_SEARCH_BING,
    ACTION_HOTKEY_SEARCH_GITHUB,
    ACTION_HOTKEY_OPEN_URL,
)

# Decompiler view hotkeys
# HTC: V duplicate with HexCodeXplorer plugin ctree_item_vew, so change to Alt-R
ACTION_HX_REMOVE_RET_TYPE = ("lazyida::hx_removerettype", "Remove return type", "Alt-R", "Set return type of current function to void")

u16 = lambda x: unpack("<H", x)[0]
u32 = lambda x: unpack("<I", x)[0]
u64 = lambda x: unpack("<Q", x)[0]

LAZY_ARCH = 0
LAZY_BITS = 0

def copy_to_clip(data):
    QApplication.clipboard().setText(data.strip())

def clip_text():
    text = QApplication.clipboard().text()
    if not PY3 and isinstance(text, unicode):
        text = text.encode('utf-8')
    return text.strip()

# -----------------------------------------------------------------------------
# HTC -> begin

class RangeForm(idaapi.Form):
    """
    Form to prompt for selecting a range: start ea, size or end ea
    """
    def __init__(self, start_ea, end_ea):
        idaapi.Form.__init__(self, r"""Confirm or change the selected range

{FormChangeCb}
<##Start EA             :{intStartEA}>
<##Size                 :{intSize}>
<##End EA (not included):{intEndEA}>
""", {
    'intStartEA': idaapi.Form.NumericInput(swidth=20, tp=idaapi.Form.FT_HEX, value=start_ea),
    'intSize': idaapi.Form.NumericInput(swidth=20, tp=idaapi.Form.FT_HEX, value=end_ea - start_ea),
    'intEndEA': idaapi.Form.NumericInput(swidth=20, tp=idaapi.Form.FT_HEX, value=end_ea),
    'FormChangeCb': idaapi.Form.FormChangeCb(self.OnFormChange),
})

    def OnFormChange(self, fid):
        # Set initial state
        if fid == -1:
            self.EnableField(self.intEndEA, False)

        start = self.GetControlValue(self.intStartEA)
        size = self.GetControlValue(self.intSize)
        if start and size:
            self.SetControlValue(self.intEndEA, start + size)

        return 1


def plg_print(smsg):
    print("[%s] %s" % (PLUGIN_NAME, smsg))

def is_valid_addr(ea):
    return idc.get_inf_attr(idc.INF_MIN_EA) <= ea <= idc.get_inf_attr(idc.INF_MAX_EA)

def parse_location(text):
    """Parse text to hex ea or try to get a valid name - HTC"""
    plg_print("Clipboard text is '%s'" % text)

    if not text:
        return idaapi.BADADDR

    strs = re.findall(r"[\da-f]+", text, re.IGNORECASE)   # parse hex number
    if strs:
        for s in strs:
            try:
                ea = int(s, 16)
                if is_valid_addr(ea):
                    return ea
            except:
                pass

    # Fail to find a valid ea, assume text is a name
    ea = idc.get_name_ea_simple(text)
    if is_valid_addr(ea):
        return ea

    # Try to sanitize the name
    san = ida_name.validate_name(text, ida_name.VNT_IDENT)
    if san:
        ea = idc.get_name_ea_simple(san)
        if is_valid_addr(ea):
            return ea

    # Parse text into words, assume every words is a valid name
    strs = re.findall(r"\w+", text)
    if strs:
        for s in strs:
            ea = idc.get_name_ea_simple(s)
            if is_valid_addr(ea):
                return ea

    return idaapi.BADADDR

def lazy_read_selection():
    # HTC - Ignore the byte at end address
    sel, start, end = idaapi.read_range_selection(None)
    if not sel:
        if idc.get_item_size(idc.get_screen_ea()):
            start = idc.get_screen_ea()
            end = start + idc.get_item_size(start)
            sel = True

    if not sel:
        start = idaapi.BADADDR
        end = idaapi.BADADDR
    else:
        rFrm = RangeForm(start, end)
        rFrm.Compile()
        ok = rFrm.Execute()
        if ok == 1:
            # OK
            start = rFrm.intStartEA.value
            end = start + rFrm.intSize.value
        else:
            # Cancel
            sel = False

        rFrm.Free()

    # Ensure we have at least one byte
    if end <= start:
        sel = False

    return sel, start, end

def goto_clip_text():
    loc = parse_location(clip_text())
    if loc != idaapi.BADADDR:
        plg_print("Goto location 0x%X" % loc)
        idc.jumpto(loc)
        return 1

    plg_print("Failed to get a valid ea")
    return 0

def str2hex(txt):
    if not txt:
        return 0

    # is it a valid number ?
    val = 0
    if txt.endswith("h"):
        txt = txt[:-1]
    try:
        val = int(txt, 16)
    except:
        pass

    return val

def get_number_from_highlight():
    view = idaapi.get_current_viewer()
    thing = ida_kernwin.get_highlight(view)
    if thing and thing[1]:
        # we have a highlight
        val = str2hex(thing[0])
        if val != 0:
            # have a valid hex number
            return val

    return str2hex(clip_text())

def goto_rva():
    rva = get_number_from_highlight()
    rva = ida_kernwin.ask_addr(rva, "Enter the RVA to jump to")
    if rva is None:
        return 0

    base = ida_nalt.get_imagebase()
    ea = base + rva
    plg_print("RVA = 0x%X -> EA = 0x%X" % (rva, ea))
    idc.jumpto(ea)
    return 1

def goto_file_ofs():
    fofs = get_number_from_highlight()
    fofs = ida_kernwin.ask_addr(fofs, "Enter the file offset to jump to")
    if fofs is None:
        return 0

    ea = idaapi.get_fileregion_ea(fofs)
    if ea != idc.BADADDR:
        plg_print("File offset = 0x%X -> EA = 0x%X" % (fofs, ea))
        idc.jumpto(ea)
        return 1
    else:
        plg_print("Invalid file offset 0x%X" % fofs)
        return 0

def copy_rva():
    ea = idc.get_screen_ea()
    base = ida_nalt.get_imagebase()
    rva = ea - base
    plg_print("EA = 0x%X - RVA = 0x%X copied to clipboard" % (ea, rva))
    copy_to_clip("0x%X" % rva)

def copy_file_offset():
    ea = idc.get_screen_ea()
    fofs = ida_loader.get_fileregion_offset(ea)
    if fofs == -1:
        plg_print("File offset unknown")
        return 0

    plg_print("EA = 0x%X -> file offset = 0x%X copied to clipboard" % (ea, fofs))
    copy_to_clip("0x%X" % fofs)
    return 1

# Org code of William Ballethin (FireEye) - hints-call plugin
# Thanks Willi :)
def get_ea_from_highlight():
    view = idaapi.get_current_viewer()
    thing = ida_kernwin.get_highlight(view)
    if thing and thing[1]:
        # we have a highligh, is it a valid name ?
        ea = idc.get_name_ea_simple(thing[0])
        if ea != idaapi.BADADDR:
            return ea

        # get name at screen ea
        ea = idc.get_screen_ea()
        name = idc.get_name(ea, idaapi.GN_DEMANGLED)
        if name and thing[0] in name:
            return ea

        # are we at end of function ?
        fn = idaapi.get_func(ea)
        if fn:
            if ea == fn.end_ea or idc.next_head(ea) == fn.end_ea:
                name = idc.get_name(fn.start_ea, idaapi.GN_DEMANGLED)
                if name and thing[0] in name:
                    return fn.start_ea

        # Try to get full highlight name
        place = idaapi.get_custom_viewer_place(view, False)
        if place and len(place) == 3:   # (plate_t, x, y)
            ea = place[0].toea()
            far_code_refs = [xref.to for xref in idautils.XrefsFrom(ea, ida_xref.XREF_FAR)]
            if far_code_refs:
                return far_code_refs[0] # First xref

    # Reach now, we do not have any valid name, return current screen ea
    return idc.get_screen_ea()

def copy_highlight_name():
    ea = get_ea_from_highlight()
    if ea != idaapi.BADADDR:
        name = idc.get_name(ea)
        if not name:
            name = "0x%X" % ea  # copy ea
        copy_to_clip(name)
        plg_print("'%s' copied to clipboard" % name)
        return True
    else:
        plg_print("Invalid ea to copy")
        return False

def paste_highlight_name():
    ea = get_ea_from_highlight()
    if ea != idaapi.BADADDR:
        name = clip_text()
        if name:
            if not ida_name.force_name(ea, name):
                name = ida_name.validate_name(name, ida_name.VNT_IDENT)
                if not ida_name.force_name(ea, name):
                    plg_print("FAILED to set name '%s' to 0x%X" % (name, ea))
                    return False

            plg_print("Set name '%s' to 0x%X" % (name, ea))
            return True
        else:
            plg_print("Clipboard is empty")
    else:
        plg_print("Invalid ea to paste")

    return False

def get_selected_text():
    """ Get the highlight text. If none, force IDA copy text and we will get from clipboard """
    text = ""
    old_text = clip_text()

    view = idaapi.get_current_viewer()
    if view:
        thing = ida_kernwin.get_highlight(view)
        if thing and thing[1]:
            text = thing[0]

    # We not have a highlight text
    if not text:
        for action in idaapi.get_registered_actions():
            if "Copy" in action:
                shortcut = idaapi.get_action_shortcut(action)
                state = idaapi.get_action_state(action)
                if ("Ctrl-C" in shortcut) and (state and state[0] and (state[1] <= idaapi.AST_ENABLE)):
                    idaapi.process_ui_action(action)
                    text = clip_text()
                    if text != old_text:
                        break

    if not text:
        plg_print("Could not get any highlight/auto copied text\n" \
                  "Search with old clipboard text: '%s'" % old_text)
        text = old_text

    return text

def search_google():
    text = get_selected_text()
    if text:
        idaapi.open_url("https://www.google.com/search?q=\"" + text + "\"")

def search_msdoc():
    text = get_selected_text()
    if text:
        idaapi.open_url("https://docs.microsoft.com/en-us/search/?terms=\"" + text + "\"")

def search_bing():
    text = get_selected_text()
    if text:
        idaapi.open_url("https://www.bing.com/search?q=\"" + text + "\"")

def search_github():
    text = get_selected_text()
    if text:
        idaapi.open_url("https://github.com/search?q=\"" + text + "\"&type=code")

def dump_data_to_file(fName, data):
    defPath = os.path.dirname(idaapi.get_input_file_path())
    defPath = os.path.join(defPath, fName)
    dumpPath = idaapi.ask_file(1, defPath, "*.dump")
    if dumpPath:
        try:
            with open(dumpPath, "wb") as f:
                f.write(data)
            plg_print("Dump %d bytes to file %s successed" % (len(data), dumpPath))
        except IOError as e:
            plg_print(str(e))

def process_data_result(start, data):
    # 16 bytes on a line
    # one byte take 4 char: 2 hex char, a space and a char if isalnum
    # one line take 3 char addtion: two space and \n, and ea hex address

    BYTES_PER_LINE = 16
    MAX_BYTES_HEX_DUMP = BYTES_PER_LINE * 64    # 64 lines

    printLen = len(data)
    if printLen > MAX_BYTES_HEX_DUMP:
        printLen = MAX_BYTES_HEX_DUMP
        plg_print("Only hexdump first %d bytes" % MAX_BYTES_HEX_DUMP)

    nLines = printLen // BYTES_PER_LINE     # Number of lines
    nOdd = printLen % BYTES_PER_LINE    # Number of bytes at last line
    isStr = True
    sHex = str()
    for i in range(printLen):
        if isStr and chr(data[i]) not in string.printable:
            isStr = False

        if i % BYTES_PER_LINE == 0:
            sHex += "%s: " % idaapi.ea2str(start + i)

        sHex += "%02X " % data[i]

        if (i % BYTES_PER_LINE == BYTES_PER_LINE - 1) or (i == printLen - 1):
            # add the end of data or end of a line
            if nLines:
                lineIdx = i // BYTES_PER_LINE   # current line number
                low = lineIdx * BYTES_PER_LINE
                high = i + 1
            else:
                low = 0
                high = printLen

            sHex += " "

            # Padding last line
            if i == printLen - 1 and nLines and nOdd:
                sHex += " " * (BYTES_PER_LINE - nOdd) * 3

            for j in range(low, high):
                ch = chr(data[j])
                sHex += ch if ch.isalnum() else "."

            sHex += "\n"

    # Print out the hexdump string
    print(sHex)

    if isStr:
        txt = str(data)
        print("String result: '%s'" % txt)
        idaapi.set_cmt(start, txt, 1)

    if idaapi.ask_yn(idaapi.ASKBTN_NO, "Do you want to patch selected range with result data ?") == idaapi.ASKBTN_YES:
        idaapi.patch_bytes(start, bytes(data))

    if idaapi.ask_yn(idaapi.ASKBTN_YES, "Do you want to dump result data to file ?") == idaapi.ASKBTN_YES:
        dump_data_to_file("Dump_At_0x%X_Size_%d.dump" % (start, len(data)), data)

def base64_decode(std):
    addr = idc.BADADDR
    ea = idc.get_screen_ea()
    flags = idaapi.get_flags(ea)

    if idc.is_strlit(flags):
        addr = ea   #  cursor is on the string
    elif idc.is_code(flags):
        addr = idc.get_first_dref_from(ea)  # get data reference from the instruction

    if addr == idc.BADADDR:
        plg_print("No string or reference to the string found\n")
        return

    b64str_enc = None
    try:
        b64str_enc = idc.get_strlit_contents(addr, -1, idc.get_str_type(addr))
    except:
        pass

    if not b64str_enc:
        plg_print("Could not get string at address 0x%X" % addr)
        return

    try:
        b64str_dec = base64.standard_b64decode(b64str_enc) if std else base64.urlsafe_b64decode(b64str_enc)
    except Exception as e:
        plg_print("Could not decode. %s" % str(e))
        return

    if b64str_dec:
        plg_print("Base64 decode of string '%s':" % b64str_enc)
        process_data_result(ea, bytearray(b64str_dec))

# HTC -> end
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# NgonNguyen & HTC -> begin

def str_to_bytes(sInput):
    """ str -> bytearray """
    try:
        s = sInput.strip()  # remove trailing white spaces
        if s.startswith('"') or s.startswith("'"):
            s = s[1:]
        if s.endswith('"') or s.endswith("'"):
            s = s[:-1]
        return bytearray(s.encode("utf-8"))
    except:
        return None

def hex_to_bytes(sInput):
    """ hex str to bytearray """
    s = sInput.lower().replace('0x', '').replace('\\x', '')
    s = ''.join(s.split())  # remove all white space
    try:
        s = bytearray(binascii.a2b_hex(s))
    except:
        plg_print("Invalid hex string input '%s'" % sInput)
        s = None
    return s

def is_str(s):
    return s.startswith(('"', '\'')) or s.endswith(('"', '\''))

def xor_data(data, key):
    """
    data: bytes
    key: bytes

    return: bytes
    """
    output = bytearray(len(data))
    for i in range(len(data)):
        output[i] = data[i] ^ key[i % len(key)]
    return output

def nop_hider():
    hides = []
    in_nop_sled = 0
    curr_pos = 0
    sled_len = 0

    for seg_ea in idautils.Segments():
        for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
            if idc.is_code(idc.get_full_flags(head)):
                mnem = idc.print_insn_mnem(head)
                if mnem == 'nop':
                    sled_len += 1
                    if in_nop_sled == 0:
                        curr_pos = head
                        in_nop_sled = 1
                else :
                    if in_nop_sled == 1 :
                        in_nop_sled = 0
                        hides.append([curr_pos, sled_len])
                        curr_pos = 0
                        sled_len = 0

    if len(hides) == 0:
        plg_print("Found nothing NOPs block")

    for h in hides:
        if h[1] > 1:
            plg_print("Hide range: 0x%X - 0x%X" % (h[0], h[0] + h[1]))
            idc.add_hidden_range(h[0], h[0] + h[1], '[NOPs]', '', '', 0xFFFFFF)
            idc.update_hidden_range(h[0], False)

    plg_print("Hidding %d NOPs block" % len(hides))

def turn_off_ida_decision():
    sel, start, end = lazy_read_selection()
    if not sel:
        return 0

    plg_print("Turn off IDA auto analysis for range 0x%X - 0x%X" % (start, end - 1))
    idaapi.revert_ida_decisions(start, end)

# NgonNguyen & HTC -> end
# -----------------------------------------------------------------------------

class VulnChoose(idaapi.Choose):
    """
    Chooser class to display result of format string vuln scan
    """
    def __init__(self, title, items, icon, embedded=False):
        idaapi.Choose.__init__(self, title, [["Address", 20], ["Function", 30], ["Format", 30]], embedded=embedded)
        self.items = items
        self.icon = 45

    def GetItems(self):
        return self.items

    def SetItems(self, items):
        self.items = [] if items is None else items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        idc.jumpto(int(self.items[n][0], 16))


class hotkey_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for hotkey actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action == ACTION_HOTKEY_COPY_EA[0]:
            ea = idc.get_screen_ea()
            copy_to_clip("0x%X" % ea)
            plg_print("Address '0x%X' copied to clipboard" % ea)
        elif self.action == ACTION_HOTKEY_COPY_RVA[0]:
            copy_rva()
        elif self.action == ACTION_HOTKEY_COPY_FOFS[0]:
            copy_file_offset()
        elif self.action == ACTION_HOTKEY_COPY_NAME[0]:
            copy_highlight_name()
        elif self.action == ACTION_HOTKEY_PASTE_NAME[0]:
            paste_highlight_name()
        elif self.action == ACTION_HOTKEY_GOTO_CLIP[0]:
            goto_clip_text()
        elif self.action == ACTION_HOTKEY_GOTO_FOFS[0]:
            goto_file_ofs()
        elif self.action == ACTION_HOTKEY_GOTO_RVA[0]:
            goto_rva()
        elif self.action == ACTION_HOTKEY_SEARCH_GOOGLE[0]:
            search_google()
        elif self.action == ACTION_HOTKEY_SEARCH_MSDOC[0]:
            search_msdoc()
        elif self.action == ACTION_HOTKEY_SEARCH_BING[0]:
            search_bing()
        elif self.action == ACTION_HOTKEY_SEARCH_GITHUB[0]:
            search_github()
        elif self.action == ACTION_HOTKEY_OPEN_URL[0]:
            text = get_selected_text()
            if text:
                idaapi.open_url(text)
        else:
            return 0

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class menu_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for menu actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action in ACTION_MENU_CONVERT:
            sel, start, end = lazy_read_selection()
            if not sel:
                idc.msg("[LazyIDA] Nothing to convert.")
                return False

            size = end - start
            data = idc.get_bytes(start, size)
            if isinstance(data, str):  # python2 compatibility
                data = bytearray(data)
            assert size == len(data)

            name = idc.get_name(start, idc.GN_VISIBLE)
            if not name:
                name = "data"
            if data:
                output = None
                plg_print("Dump from 0x%X to 0x%X (%u bytes):" % (start, end - 1, size))
                if self.action == ACTION_MENU_CONVERT[0]:
                    # escaped string
                    output = '"%s"' % "".join("\\x%02X" % b for b in data)

                elif self.action == ACTION_MENU_CONVERT[1]:
                    # hex string, space
                    output = " ".join("%02X" % b for b in data)

                elif self.action == ACTION_MENU_CONVERT[2]:
                    # C array
                    output = "unsigned char %s[%d] = {" % (name, size)
                    for i in range(size):
                        if i % 16 == 0:
                            output += "\n    "
                        output += "0x%02X, " % data[i]
                    output = output[:-2] + "\n};"

                elif self.action == ACTION_MENU_CONVERT[3]:
                    # C array word
                    data += b"\x00"
                    array_size = (size + 1) // 2
                    output = "unsigned short %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 2):
                        if i % 16 == 0:
                            output += "\n    "
                        output += "0x%04X, " % u16(data[i:i+2])
                    output = output[:-2] + "\n};"

                elif self.action == ACTION_MENU_CONVERT[4]:
                    # C array dword
                    data += b"\x00" * 3
                    array_size = (size + 3) // 4
                    output = "unsigned int %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 4):
                        if i % 32 == 0:
                            output += "\n    "
                        output += "0x%08X, " % u32(data[i:i+4])
                    output = output[:-2] + "\n};"

                elif self.action == ACTION_MENU_CONVERT[5]:
                    # C array qword
                    data += b"\x00" * 7
                    array_size = (size + 7) // 8
                    output = "unsigned __int64 %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 8):
                        if i % 32 == 0:
                            output += "\n    "
                        output += "%#018X, " % u64(data[i:i+8])
                    output = output[:-2] + "\n};"
                    output = output.replace("0X", "0x")

                elif self.action == ACTION_MENU_CONVERT[6]:
                    # python list
                    output = "[%s]" % ", ".join("0x%02X" % b for b in data)

                elif self.action == ACTION_MENU_CONVERT[7]:
                    # python list word
                    data += b"\x00"
                    output = "[%s]" % ", ".join("0x%04X" % u16(data[i:i+2]) for i in range(0, size, 2))

                elif self.action == ACTION_MENU_CONVERT[8]:
                    # python list dword
                    data += b"\x00" * 3
                    output = "[%s]" % ", ".join("0x%08X" % u32(data[i:i+4]) for i in range(0, size, 4))

                elif self.action == ACTION_MENU_CONVERT[9]:
                    # python list qword
                    data += b"\x00" * 7
                    output = "[%s]" %  ", ".join("%#018X" % u64(data[i:i+8]) for i in range(0, size, 8)).replace("0X", "0x")

                elif self.action == ACTION_MENU_CONVERT[10]:
                    # MASM byte array
                    header = "%s db " % name
                    output = header
                    for i in range(size):
                        if i and i % 16 == 0:
                            output += "\n"
                            output += " " * len(header)
                        output += "0%02Xh, " % data[i]
                    output = output[:-2]

                elif self.action == ACTION_MENU_CONVERT[11]:
                    # GNU ASM byte array
                    header = "%s: .byte " % name
                    output = header
                    for i in range(size):
                        if i and i % 16 == 0:
                            output += "\n"
                            output += " " * len(header)
                        output += "0x%02X, " % data[i]
                    output = output[:-2]

                if output:
                    print(output)
                    copy_to_clip(output)
                    output = None

        elif self.action == ACTION_MENU_COPY_DATA:
            # added by merc, modified by HTC
            sel, start, end = lazy_read_selection()
            if not sel:
                return 0

            data = idaapi.get_bytes(start, end - start)
            if isinstance(data, str):
                data = bytearray(data)
            output = "".join("%02X" % b for b in data)
            copy_to_clip(output)
            plg_print("Hex string '%s' copied" % output)

        elif self.action == ACTION_MENU_DUMP_DATA:
            # add by HTC
            sel, start, end = lazy_read_selection()
            if not sel:
                return 0

            size = end - start
            data = idaapi.get_bytes(start, size)
            assert len(data) == size
            if data and len(data) == size:
                dump_data_to_file("Dump_At_%X_Size_%d.dump" % (start, size), data)
            else:
                plg_print("0x%X: unable to get %d bytes" % (start, size))

        elif self.action == ACTION_MENU_XOR_DATA:
            sel, start, end = lazy_read_selection()
            if not sel:
                return 0

            size = end - start

            key = idaapi.ask_str("AA BB CC DD", 0, "Xor with hex values (or a string begin and end with\" or ')...")
            if not key:
                return 0

            bytes_key = bytearray()
            if is_str(key):
                bytes_key = str_to_bytes(key)
            else:
                bytes_key = hex_to_bytes(key)

            if not bytes_key:
                return 0

            data = idc.get_bytes(start, end - start)
            if isinstance(data, str):  # python2 compatibility
                data = bytearray(data)

            output = xor_data(data, bytes_key)
            if not output:
                plg_print("Sorry, error occurred. My bug :( Please report.")
                return 0

            assert size == len(output)

            plg_print("Xor result from 0x%X to 0x%X (%d bytes) with %s:" % (start, end, end - start, key))
            process_data_result(start, output)

        elif self.action == ACTION_MENU_FILL_NOP:
            sel, start, end = lazy_read_selection()
            if not sel:
                return 0

            idaapi.patch_bytes(start, b"\x90" * (end - start))
            idc.create_insn(start)
            plg_print("Fill 0x%X to 0x%X (%u bytes) with NOPs" % (start, end, end - start))

        elif self.action == ACTION_MENU_NOP_HIDER:
            nop_hider()

        elif self.action == ACTION_MENU_AUTO_OFF:
            turn_off_ida_decision()

        elif self.action == ACTION_MENU_B64STD:
            base64_decode(True)

        elif self.action == ACTION_MENU_B64URL:
            base64_decode(False)

        elif self.action == ACTION_MENU_SCAN_VUL:
            plg_print("Finding Format String Vulnerability...")
            found = []
            for addr in idautils.Functions():
                name = idc.get_func_name(addr)
                if "printf" in name and "v" not in name and idc.get_segm_name(addr) in (".text", ".plt", ".idata"):
                    xrefs = idautils.CodeRefsTo(addr, False)
                    for xref in xrefs:
                        vul = self.check_fmt_function(name, xref)
                        if vul:
                            found.append(vul)
            if found:
                plg_print("Done! %d possible vulnerabilities found." % len(found))
                ch = VulnChoose("Vulnerability", found, None, False)
                ch.Show()
            else:
                plg_print("No format string vulnerabilities found.")

        else:
            return 0

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.form_type in (idaapi.BWN_DISASM, idaapi.BWN_DUMP) \
            else idaapi.AST_DISABLE_FOR_WIDGET

    @staticmethod
    def check_fmt_function(name, addr):
        """
        Check if the format string argument is not valid
        """
        function_head = idc.get_func_attr(addr, idc.FUNCATTR_START)

        while True:
            addr = idc.prev_head(addr)
            op = idc.print_insn_mnem(addr).lower()
            dst = idc.print_operand(addr, 0)

            if op in ("ret", "retn", "jmp", "b") or addr < function_head:
                return None

            c = idc.get_cmt(addr, 0)
            if c and c.lower() == "format":
                break
            elif name.endswith(("snprintf_chk",)):
                if op in ("mov", "lea") and dst.endswith(("r8", "r8d", "[esp+10h]")):
                    break
            elif name.endswith(("sprintf_chk",)):
                if op in ("mov", "lea") and (dst.endswith(("rcx", "[esp+0Ch]", "R3")) or
                                             dst.endswith("ecx") and LAZY_BITS == 64):
                    break
            elif name.endswith(("snprintf", "fnprintf")):
                if op in ("mov", "lea") and (dst.endswith(("rdx", "[esp+8]", "R2")) or
                                             dst.endswith("edx") and LAZY_BITS == 64):
                    break
            elif name.endswith(("sprintf", "fprintf", "dprintf", "printf_chk")):
                if op in ("mov", "lea") and (dst.endswith(("rsi", "[esp+4]", "R1")) or
                                             dst.endswith("esi") and LAZY_BITS == 64):
                    break
            elif name.endswith("printf"):
                if op in ("mov", "lea") and (dst.endswith(("rdi", "[esp]", "R0")) or
                                             dst.endswith("edi") and LAZY_BITS == 64):
                    break

        # format arg found, check its type and value
        # get last oprend
        op_index = idc.generate_disasm_line(addr, 0).count(",")
        op_type = idc.get_operand_type(addr, op_index)
        opnd = idc.print_operand(addr, op_index)

        if op_type == idc.o_reg:
            # format is in register, try to track back and get the source
            _addr = addr
            while True:
                _addr = idc.prev_head(_addr)
                _op = idc.print_insn_mnem(_addr).lower()
                if _op in ("ret", "retn", "jmp", "b") or _addr < function_head:
                    break
                elif _op in ("mov", "lea", "ldr") and idc.print_operand(_addr, 0) == opnd:
                    op_type = idc.get_operand_type(_addr, 1)
                    opnd = idc.print_operand(_addr, 1)
                    addr = _addr
                    break

        if op_type in (idc.o_imm, idc.o_mem):
            # format is a memory address, check if it's in writable segment
            op_addr = idc.get_operand_value(addr, op_index)
            seg = idaapi.getseg(op_addr)
            if seg:
                if not seg.perm & idaapi.SEGPERM_WRITE:
                    # format is in read-only segment
                    return None

        plg_print("0x%X: Possible Vulnerability: %s, format = %s" % (addr, name, opnd))
        return ["0x%X" % addr, name, opnd]


class hexrays_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for hexrays actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action
        self.ret_type = {}

    def activate(self, ctx):
        if self.action == ACTION_HX_REMOVE_RET_TYPE[0]:
            vdui = idaapi.get_widget_vdui(ctx.widget)
            self.remove_rettype(vdui)
            vdui.refresh_ctext()
        else:
            return 0

        return 1

    def update(self, ctx):
        vdui = idaapi.get_widget_vdui(ctx.widget)
        return idaapi.AST_ENABLE_FOR_WIDGET if vdui else idaapi.AST_DISABLE_FOR_WIDGET

    def remove_rettype(self, vu):
        if vu.item.citype == idaapi.VDI_FUNC:
            # current function
            ea = vu.cfunc.entry_ea
            old_func_type = idaapi.tinfo_t()
            if not vu.cfunc.get_func_type(old_func_type):
                return False
        elif vu.item.citype == idaapi.VDI_EXPR and vu.item.e.is_expr() and vu.item.e.type.is_funcptr():
            # call xxx
            ea = vu.item.get_ea()
            old_func_type = idaapi.tinfo_t()

            func = idaapi.get_func(ea)
            if func:
                try:
                    cfunc = idaapi.decompile(func)
                except idaapi.DecompilationFailure:
                    return False

                if not cfunc.get_func_type(old_func_type):
                    return False
            else:
                return False
        else:
            return False

        fi = idaapi.func_type_data_t()
        if ea != idaapi.BADADDR and old_func_type.get_func_details(fi):
            # Return type is already void
            if fi.rettype.is_decl_void():
                # Restore ret type
                if ea not in self.ret_type:
                    return True
                ret = self.ret_type[ea]
            else:
                # Save ret type and change it to void
                self.ret_type[ea] = fi.rettype
                ret = idaapi.BT_VOID

            # Create new function info with new rettype
            fi.rettype = idaapi.tinfo_t(ret)

            # Create new function type with function info
            new_func_type = idaapi.tinfo_t()
            new_func_type.create_func(fi)

            # Apply new function type
            if idaapi.apply_tinfo(ea, new_func_type, idaapi.TINFO_DEFINITE):
                return vu.refresh_view(True)

        return False


class UI_Hook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, widget, popup):
        # attach Searchs menu to all widget
        idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_SEARCH_GOOGLE[0], "LazyIDA/")
        idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_SEARCH_MSDOC[0], "LazyIDA/")
        idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_SEARCH_BING[0], "LazyIDA/")
        idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_SEARCH_GITHUB[0], "LazyIDA/")
        idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_OPEN_URL[0], "LazyIDA/")
        idaapi.attach_action_to_popup(widget, popup, None, "LazyIDA/")

        widget_type = idaapi.get_widget_type(widget)
        if widget_type in [idaapi.BWN_DISASM, idaapi.BWN_DUMP]:
            for action in ACTION_MENU_CONVERT:
                idaapi.attach_action_to_popup(widget, popup, action, "LazyIDA/Convert/")

            idaapi.attach_action_to_popup(widget, popup, None, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_MENU_COPY_DATA, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_MENU_DUMP_DATA, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_MENU_XOR_DATA, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_MENU_FILL_NOP, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_MENU_NOP_HIDER, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_MENU_AUTO_OFF, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, None, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_MENU_B64STD, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_MENU_B64URL, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, None, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_COPY_EA[0], "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_COPY_RVA[0], "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_COPY_FOFS[0], "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, None, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_COPY_NAME[0], "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_PASTE_NAME[0], "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, None, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_GOTO_CLIP[0], "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_GOTO_FOFS[0], "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_HOTKEY_GOTO_RVA[0], "LazyIDA/")

        if widget_type == idaapi.BWN_DISASM and (LAZY_ARCH, LAZY_BITS) in [(idaapi.PLFM_386, 32),
                                                                           (idaapi.PLFM_386, 64),
                                                                           (idaapi.PLFM_ARM, 32),]:
            idaapi.attach_action_to_popup(widget, popup, None, "LazyIDA/")
            idaapi.attach_action_to_popup(widget, popup, ACTION_MENU_SCAN_VUL, "LazyIDA/")


class HexRays_Hook(object):
    def callback(self, event, *args):
        if event == idaapi.hxe_populating_popup:
            form, phandle, vu = args
            if vu.item.citype == idaapi.VDI_FUNC or (vu.item.citype == idaapi.VDI_EXPR and vu.item.e.is_expr() and vu.item.e.type.is_funcptr()):
                idaapi.attach_action_to_popup(form, phandle, ACTION_HX_REMOVE_RET_TYPE[0], None)
        elif event == idaapi.hxe_double_click:
            vu, _shift_state = args
            # auto jump to target if clicked item is xxx->func();
            if vu.item.citype == idaapi.VDI_EXPR and vu.item.e.is_expr():
                expr = idaapi.tag_remove(vu.item.e.print1(None))
                if "->" in expr:
                    # find target function
                    name = expr.split("->")[-1]
                    addr = idc.get_name_ea_simple(name)
                    if addr == idaapi.BADADDR:
                        # try class::function
                        e = vu.item.e
                        while e.x:
                            e = e.x
                        addr = idc.get_name_ea_simple("%s::%s" % (str(e.type).split()[0], name))

                    if addr != idaapi.BADADDR:
                        idc.jumpto(addr)
                        return 1
        return 0


class LazyIDA_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE   # | idaapi.PLUGIN_UNL for fix bugs, debug
    comment = PLUGIN_NAME
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def __init__(self):
        self.ui_hook = None
        self.hx_hook = None
        self.hexrays_inited = False
        self.registered_hotkey_actions = []
        self.registered_menu_actions = []
        self.registered_hexray_actions = []

    def init(self):
        global LAZY_ARCH
        global LAZY_BITS
        LAZY_ARCH = idaapi.ph_get_id()
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            LAZY_BITS = 64
        elif info.is_32bit():
            LAZY_BITS = 32
        else:
            LAZY_BITS = 16

        plg_print("v1.0.0.4 - plugin has been loaded.")

        # Register hotkey actions
        for HK_ACT in ALL_HOTKEY_ACTIONS:
            action = idaapi.action_desc_t(HK_ACT[0],    # name
                                          HK_ACT[1],    # label
                                          hotkey_action_handler_t(HK_ACT[0]), # action handler
                                          HK_ACT[2],    # shortcut
                                          HK_ACT[3],    # tooltip
                                          HK_ACT[4])    # iconid
            idaapi.register_action(action)
            self.registered_hotkey_actions.append(action.name)

        # Register menu actions
        menu_actions = (
            idaapi.action_desc_t(ACTION_MENU_CONVERT[0], "Convert to string", menu_action_handler_t(ACTION_MENU_CONVERT[0]), None, None, 80),
            idaapi.action_desc_t(ACTION_MENU_CONVERT[1], "Convert to hex string space", menu_action_handler_t(ACTION_MENU_CONVERT[1]), None, None, 8),
            idaapi.action_desc_t(ACTION_MENU_CONVERT[2], "Convert to C/C++ array (BYTE)", menu_action_handler_t(ACTION_MENU_CONVERT[2]), None, None, 38),
            idaapi.action_desc_t(ACTION_MENU_CONVERT[3], "Convert to C/C++ array (WORD)", menu_action_handler_t(ACTION_MENU_CONVERT[3]), None, None, 38),
            idaapi.action_desc_t(ACTION_MENU_CONVERT[4], "Convert to C/C++ array (DWORD)", menu_action_handler_t(ACTION_MENU_CONVERT[4]), None, None, 38),
            idaapi.action_desc_t(ACTION_MENU_CONVERT[5], "Convert to C/C++ array (QWORD)", menu_action_handler_t(ACTION_MENU_CONVERT[5]), None, None, 38),
            idaapi.action_desc_t(ACTION_MENU_CONVERT[6], "Convert to python list (BYTE)", menu_action_handler_t(ACTION_MENU_CONVERT[6]), None, None, 201),
            idaapi.action_desc_t(ACTION_MENU_CONVERT[7], "Convert to python list (WORD)", menu_action_handler_t(ACTION_MENU_CONVERT[7]), None, None, 201),
            idaapi.action_desc_t(ACTION_MENU_CONVERT[8], "Convert to python list (DWORD)", menu_action_handler_t(ACTION_MENU_CONVERT[8]), None, None, 201),
            idaapi.action_desc_t(ACTION_MENU_CONVERT[9], "Convert to python list (QWORD)", menu_action_handler_t(ACTION_MENU_CONVERT[9]), None, None, 201),
            idaapi.action_desc_t(ACTION_MENU_CONVERT[10], "Convert to MASM array (BYTE)", menu_action_handler_t(ACTION_MENU_CONVERT[10]), None, None, 38),
            idaapi.action_desc_t(ACTION_MENU_CONVERT[11], "Convert to GNU ASM array (BYTE)", menu_action_handler_t(ACTION_MENU_CONVERT[11]), None, None, 38),
            idaapi.action_desc_t(ACTION_MENU_COPY_DATA, "Copy hex data to clipboard", menu_action_handler_t(ACTION_MENU_COPY_DATA), None, None, 9),
            idaapi.action_desc_t(ACTION_MENU_DUMP_DATA, "Dump data to file", menu_action_handler_t(ACTION_MENU_DUMP_DATA), None, None, 0x1B),
            idaapi.action_desc_t(ACTION_MENU_XOR_DATA, "Get xored data", menu_action_handler_t(ACTION_MENU_XOR_DATA), None, None, 9),
            idaapi.action_desc_t(ACTION_MENU_FILL_NOP, "Fill with NOPs", menu_action_handler_t(ACTION_MENU_FILL_NOP), None, None, 9),
            idaapi.action_desc_t(ACTION_MENU_NOP_HIDER, "NOPs Hider", menu_action_handler_t(ACTION_MENU_NOP_HIDER), None, None, 9),
            idaapi.action_desc_t(ACTION_MENU_AUTO_OFF, "Revert IDA Decision", menu_action_handler_t(ACTION_MENU_AUTO_OFF), None, None, 9),
            idaapi.action_desc_t(ACTION_MENU_B64STD, "Base64Std decode", menu_action_handler_t(ACTION_MENU_B64STD), None, None, 9),
            idaapi.action_desc_t(ACTION_MENU_B64URL, "Base64Url decode", menu_action_handler_t(ACTION_MENU_B64URL), None, None, 9),
            idaapi.action_desc_t(ACTION_MENU_SCAN_VUL, "Scan format string vulnerabilities", menu_action_handler_t(ACTION_MENU_SCAN_VUL), None, None, 160),
        )
        for action in menu_actions:
            idaapi.register_action(action)
            self.registered_menu_actions.append(action.name)

        # Add ui hook
        self.ui_hook = UI_Hook()
        self.ui_hook.hook()

        # Add hexrays ui callback
        if idaapi.init_hexrays_plugin():
            hx_actions = (
                idaapi.action_desc_t(ACTION_HX_REMOVE_RET_TYPE[0],
                                     ACTION_HX_REMOVE_RET_TYPE[1],
                                     hexrays_action_handler_t(ACTION_HX_REMOVE_RET_TYPE[0]),
                                     ACTION_HX_REMOVE_RET_TYPE[2],
                                     ACTION_HX_REMOVE_RET_TYPE[3],
                                     -1),
            )
            for action in hx_actions:
                idaapi.register_action(action)
                self.registered_hexray_actions.append(action.name)

            self.hx_hook = HexRays_Hook()
            idaapi.install_hexrays_callback(self.hx_hook.callback)
            self.hexrays_inited = True

        addon = idaapi.addon_info_t()
        addon.id = "htc_lazyida"
        addon.name = "LazyIDA"
        addon.producer = "HTC (Original: Lays - tw.l4ys.lazyida)"
        addon.url = "https://github.com/HongThatCong/LazyIDA"
        addon.version = "1.0.6"
        idaapi.register_addon(addon)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.ui_hook:
            self.ui_hook.unhook()
            self.ui_hook = None

        # Unregister actions
        if self.registered_hotkey_actions:
            for action in self.registered_hotkey_actions:
                idaapi.unregister_action(action)
            del self.registered_hotkey_actions[:]

        if self.registered_menu_actions:
            for action in self.registered_menu_actions:
                idaapi.unregister_action(action)
            del self.registered_menu_actions[:]

        if self.hexrays_inited:
            if self.hx_hook:
                idaapi.remove_hexrays_callback(self.hx_hook.callback)
                self.hx_hook = None

            # Unregister hexrays actions
            if self.registered_hexray_actions:
                for action in self.registered_hexray_actions:
                    idaapi.unregister_action(action)
                del self.registered_hexray_actions[:]

            idaapi.term_hexrays_plugin()

        plg_print("plugin terminated")


def PLUGIN_ENTRY():
    return LazyIDA_t()
