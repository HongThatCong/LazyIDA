# https://github.com/L4ys/LazyIDA
# https://github.com/HongThatCong/LazyIDA

# pylint: disable=C0301,C0103,C0111

# 09/08/2020 - HTC (VinCSS)
#   - fix bug read_selection
#   - fix bug parse_location, so Shift-G hotkey can jumpto any ea, name possibles
#   - change "C" hotkey to Shift-C, because C is duplicate function with IDA Ctrl-C hotkey
#     Shift-C will copy full name of a current highlight name
#   - add "Shfit-V" hotkey, paste name from clipboard to current highlight name or current addr (fullname)
# 10/08/2020
#   - Fix bug sanitize name from clipboard text - Ngon Nguyen

from __future__ import division
from __future__ import print_function

from struct import unpack
import re

import idaapi
import idautils
import idc
import ida_kernwin
import ida_xref
import ida_name

from PyQt5.Qt import QApplication

# Popup menus
ACTION_CONVERT = ["lazyida:convert%d" % i for i in range(10)]
ACTION_SCANVUL = "lazyida:scanvul"
ACTION_COPYDATA = "lazyida:copydata"    # added by merc
ACTION_XORDATA = "lazyida:xordata"
ACTION_FILLNOP = "lazyida:fillnop"

# ASM view hotkeys
ACTION_COPYEA = "lazyida:copyea"        # W hotkey
ACTION_COPYNAME = "lazyida:copyname"    # add by HTC, Shift-C hotkey
ACTION_PASTENAME = "lazyida:pastedata"  # add by HTC, Shift-V hotkey
ACTION_GOTOCLIP = "lazyida:gotoclip"    # Shift-G hotkey

# Decompiler view hotkeys
ACTION_HX_REMOVERETTYPE = "lazyida:hx_removerettype"    # V hotkey, duplicate functional with HexCodeXplorer plugin
ACTION_HX_COPYEA = "lazyida:hx_copyea"                  # W hotkey
ACTION_HX_COPYNAME = "lazyida:hx_copyname"              # fix by HTC, Shift-C
ACTION_HX_PASTENAME = "lazyida:hx_pastename"            # add by HTC, Shift-V
ACTION_HX_GOTOCLIP = "lazyida:hx_gotoclip"              # Shift-G hotkey

u16 = lambda x: unpack("<H", x)[0]
u32 = lambda x: unpack("<I", x)[0]
u64 = lambda x: unpack("<Q", x)[0]

LAZY_ARCH = 0
LAZY_BITS = 0

def copy_to_clip(data):
    QApplication.clipboard().setText(data.strip())

def clip_text():
    text = QApplication.clipboard().text()
    if isinstance(text, unicode):
        text = text.encode('utf-8')
    return text.strip()

# -----------------------------------------------------------------------------
# HTC -> begin

def is_valid_addr(ea):
    return idc.get_inf_attr(idc.INF_MIN_EA) <= ea <= idc.get_inf_attr(idc.INF_MAX_EA)

def parse_location(text):
    """Parse text to hex ea or try to get a valid name - HTC"""
    print("[LazyIDA] Clipboard text %s" % text)

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

    # Parse text into words, find every word is a valid name
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

    return sel, start, end

def goto_clip_text():
    loc = parse_location(clip_text())
    if loc != idaapi.BADADDR:
        print("[LazyIDA] Goto location 0x%X" % loc)
        idc.jumpto(loc)
        return 1

    print("[LazyIDA] failed to get a valid ea")
    return 0

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
        else:
            # Try to get full highlight name
            place = idaapi.get_custom_viewer_place(view, False)
            if place and len(place) == 3:   # (plate_t, x, y)
                ea = place[0].toea()
                far_code_refs = [xref.to for xref in idautils.XrefsFrom(ea, ida_xref.XREF_FAR) \
                                 if idc.is_code(idc.get_full_flags(xref.to))]
                if far_code_refs:
                    return far_code_refs[0]

    # Reach now, we do not have any valid name, return current screen ea
    return idc.get_screen_ea()

def copy_highlight_name():
    ea = get_ea_from_highlight()
    if ea != idaapi.BADADDR:
        name = idc.get_name(ea)
        if not name:
            name = "0x%X" % ea  # copy ea
        copy_to_clip(name)
        print("[LazyIDA] '%s' copied to clipboard" % name)
        return True
    else:
        print("[LazyIDA] invalid ea to copy")
        return False

def paste_highlight_name():
    ea = get_ea_from_highlight()
    if ea != idaapi.BADADDR:
        name = clip_text()
        if name:
            if not ida_name.set_name(ea, name, ida_name.SN_AUTO | ida_name.SN_NOWARN | ida_name.SN_FORCE):
                name = ida_name.validate_name(name, ida_name.VNT_IDENT)
                if not ida_name.set_name(ea, name, ida_name.SN_AUTO | ida_name.SN_NOWARN | ida_name.SN_FORCE):
                    print("[LazyIDA] FAILED to set name '%s' to 0x%X" % (name, ea))
                    return False

            print("[LazyIDA] set name '%s' to 0x%X" % (name, ea))
            return True
        else:
            print("[LazyIDA] clipboard empty")
    else:
        print("[LazyIDA] invalid ea to paste")

    return False

# HTC -> end
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
        if self.action == ACTION_COPYEA:
            ea = idc.get_screen_ea()
            if ea != idaapi.BADADDR:
                copy_to_clip("0x%X" % ea)
                print("[LazyIDA] address '0x%X' copied to clipboard" % ea)
        elif self.action == ACTION_GOTOCLIP:
            goto_clip_text()
        elif self.action == ACTION_COPYNAME:
            copy_highlight_name()
        elif self.action == ACTION_PASTENAME:
            paste_highlight_name()

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_WIDGET if ctx.form_type in (idaapi.BWN_DISASM, idaapi.BWN_DUMP) \
            else idaapi.AST_DISABLE_FOR_WIDGET

class menu_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for menu actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action in ACTION_CONVERT:
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
                print("\n[+] Dump 0x%X - 0x%X (%u bytes) :" % (start, end, size))
                if self.action == ACTION_CONVERT[0]:
                    # escaped string
                    print('"%s"' % "".join("\\x%02X" % b for b in data))
                elif self.action == ACTION_CONVERT[1]:
                    # hex string
                    print("".join("%02X" % b for b in data))
                elif self.action == ACTION_CONVERT[2]:
                    # C array
                    output = "unsigned char %s[%d] = {" % (name, size)
                    for i in range(size):
                        if i % 16 == 0:
                            output += "\n    "
                        output += "0x%02X, " % data[i]
                    output = output[:-2] + "\n};"
                    print(output)
                elif self.action == ACTION_CONVERT[3]:
                    # C array word
                    data += b"\x00"
                    array_size = (size + 1) // 2
                    output = "unsigned short %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 2):
                        if i % 16 == 0:
                            output += "\n    "
                        output += "0x%04X, " % u16(data[i:i+2])
                    output = output[:-2] + "\n};"
                    print(output)
                elif self.action == ACTION_CONVERT[4]:
                    # C array dword
                    data += b"\x00" * 3
                    array_size = (size + 3) // 4
                    output = "unsigned int %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 4):
                        if i % 32 == 0:
                            output += "\n    "
                        output += "0x%08X, " % u32(data[i:i+4])
                    output = output[:-2] + "\n};"
                    print(output)
                elif self.action == ACTION_CONVERT[5]:
                    # C array qword
                    data += b"\x00" * 7
                    array_size = (size + 7) // 8
                    output = "unsigned long %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 8):
                        if i % 32 == 0:
                            output += "\n    "
                        output += "%#018X, " % u64(data[i:i+8])
                    output = output[:-2] + "\n};"
                    print(output.replace("0X", "0x"))
                elif self.action == ACTION_CONVERT[6]:
                    # python list
                    print("[%s]" % ", ".join("0x%02X" % b for b in data))
                elif self.action == ACTION_CONVERT[7]:
                    # python list word
                    data += b"\x00"
                    print("[%s]" % ", ".join("0x%04X" % u16(data[i:i+2]) for i in range(0, size, 2)))
                elif self.action == ACTION_CONVERT[8]:
                    # python list dword
                    data += b"\x00" * 3
                    print("[%s]" % ", ".join("0x%08X" % u32(data[i:i+4]) for i in range(0, size, 4)))
                elif self.action == ACTION_CONVERT[9]:
                    # python list qword
                    data += b"\x00" * 7
                    print("[%s]" %  ", ".join("%#018X" % u64(data[i:i+8]) for i in range(0, size, 8)).replace("0X", "0x"))
        elif self.action == ACTION_COPYDATA:
            # added by merc, modfiy by HTC
            sel, start, end = lazy_read_selection()
            if not sel:
                return 0

            data = idaapi.get_bytes(start, end - start)
            data = data.encode('hex')
            copy_to_clip(data)
            print("[LazyIDA] copied hex string '%s'" % data)
        elif self.action == ACTION_XORDATA:
            sel, start, end = lazy_read_selection()
            if not sel:
                return 0

            data = idc.get_bytes(start, end - start)
            if isinstance(data, str):  # python2 compatibility
                data = bytearray(data)
            x = idaapi.ask_long(0, "Xor with...")
            if x:
                x &= 0xFF
                print("\n[+] Xor 0x%X - 0x%X (%u bytes) with 0x%02X:" % (start, end, end - start, x))
                print(repr("".join(chr(b ^ x) for b in data)))
        elif self.action == ACTION_FILLNOP:
            sel, start, end = lazy_read_selection()
            if not sel:
                return 0
            idaapi.patch_bytes(start, b"\x90" * (end - start))
            print("\n[+] Fill 0x%X - 0x%X (%u bytes) with NOPs" % (start, end, end - start))
        elif self.action == ACTION_SCANVUL:
            print("\n[+] Finding Format String Vulnerability...")
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
                print("[!] Done! %d possible vulnerabilities found." % len(found))
                ch = VulnChoose("Vulnerability", found, None, False)
                ch.Show()
            else:
                print("[-] No format string vulnerabilities found.")
        else:
            return 0

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

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

        if op_type == idc.o_imm or op_type == idc.o_mem:
            # format is a memory address, check if it's in writable segment
            op_addr = idc.get_operand_value(addr, op_index)
            seg = idaapi.getseg(op_addr)
            if seg:
                if not seg.perm & idaapi.SEGPERM_WRITE:
                    # format is in read-only segment
                    return None

        print("0x%X: Possible Vulnerability: %s, format = %s" % (addr, name, opnd))
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
        if self.action == ACTION_HX_REMOVERETTYPE:
            vdui = idaapi.get_widget_vdui(ctx.widget)
            self.remove_rettype(vdui)
            vdui.refresh_ctext()
        elif self.action == ACTION_HX_COPYEA:
            ea = idaapi.get_screen_ea()
            if ea != idaapi.BADADDR:
                copy_to_clip("0x%X" % ea)
                print("Address 0x%X has been copied to clipboard" % ea)
        elif self.action == ACTION_HX_COPYNAME:
            copy_highlight_name()
        elif self.action == ACTION_HX_PASTENAME:
            paste_highlight_name()
        elif self.action == ACTION_HX_GOTOCLIP:
            goto_clip_text()
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
        widget_type = idaapi.get_widget_type(widget)

        if widget_type == idaapi.BWN_DISASM or widget_type == idaapi.BWN_DUMP:
            sel, _, _ = lazy_read_selection()
            if sel:
                for action in ACTION_CONVERT:
                    idaapi.attach_action_to_popup(widget, popup, action, "LazyIDA/Convert/")

                idaapi.attach_action_to_popup(widget, popup, ACTION_COPYDATA, "LazyIDA/")
                idaapi.attach_action_to_popup(widget, popup, ACTION_XORDATA, "LazyIDA/")
                idaapi.attach_action_to_popup(widget, popup, ACTION_FILLNOP, "LazyIDA/")

        if widget_type == idaapi.BWN_DISASM and (LAZY_ARCH, LAZY_BITS) in [(idaapi.PLFM_386, 32),
                                                                           (idaapi.PLFM_386, 64),
                                                                           (idaapi.PLFM_ARM, 32),]:
            idaapi.attach_action_to_popup(widget, popup, ACTION_SCANVUL, "LazyIDA/")


class HexRays_Hook(object):
    def callback(self, event, *args):
        if event == idaapi.hxe_populating_popup:
            form, phandle, vu = args
            if vu.item.citype == idaapi.VDI_FUNC or (vu.item.citype == idaapi.VDI_EXPR and vu.item.e.is_expr() and vu.item.e.type.is_funcptr()):
                idaapi.attach_action_to_popup(form, phandle, ACTION_HX_REMOVERETTYPE, None)
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
    flags = idaapi.PLUGIN_HIDE
    comment = "LazyIDA"
    help = ""
    wanted_name = "LazyIDA"
    wanted_hotkey = ""

    def init(self):
        self.hexrays_inited = False
        self.registered_actions = []
        self.registered_hx_actions = []

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

        print("[LazyIDA] v1.0.0.4 - plugin has been loaded.")

        # Register menu actions
        menu_actions = (
            idaapi.action_desc_t(ACTION_CONVERT[0], "Convert to string", menu_action_handler_t(ACTION_CONVERT[0]), None, None, 80),
            idaapi.action_desc_t(ACTION_CONVERT[1], "Convert to hex string", menu_action_handler_t(ACTION_CONVERT[1]), None, None, 8),
            idaapi.action_desc_t(ACTION_CONVERT[2], "Convert to C/C++ array (BYTE)", menu_action_handler_t(ACTION_CONVERT[2]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[3], "Convert to C/C++ array (WORD)", menu_action_handler_t(ACTION_CONVERT[3]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[4], "Convert to C/C++ array (DWORD)", menu_action_handler_t(ACTION_CONVERT[4]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[5], "Convert to C/C++ array (QWORD)", menu_action_handler_t(ACTION_CONVERT[5]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[6], "Convert to python list (BYTE)", menu_action_handler_t(ACTION_CONVERT[6]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[7], "Convert to python list (WORD)", menu_action_handler_t(ACTION_CONVERT[7]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[8], "Convert to python list (DWORD)", menu_action_handler_t(ACTION_CONVERT[8]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[9], "Convert to python list (QWORD)", menu_action_handler_t(ACTION_CONVERT[9]), None, None, 201),
            idaapi.action_desc_t(ACTION_COPYDATA, "Copy hex data to clipboard", menu_action_handler_t(ACTION_COPYDATA), None, None, 9),
            idaapi.action_desc_t(ACTION_XORDATA, "Get xored data", menu_action_handler_t(ACTION_XORDATA), None, None, 9),
            idaapi.action_desc_t(ACTION_FILLNOP, "Fill with NOPs", menu_action_handler_t(ACTION_FILLNOP), None, None, 9),
            idaapi.action_desc_t(ACTION_SCANVUL, "Scan format string vulnerabilities", menu_action_handler_t(ACTION_SCANVUL), None, None, 160),
        )
        for action in menu_actions:
            idaapi.register_action(action)
            self.registered_actions.append(action.name)

        # Register hotkey actions
        hotkey_actions = (
            idaapi.action_desc_t(ACTION_COPYEA, "Copy EA", hotkey_action_handler_t(ACTION_COPYEA),
                                 "w", "Copy current EA to clipboard", 0),
            idaapi.action_desc_t(ACTION_GOTOCLIP, "Goto clip EA/name", hotkey_action_handler_t(ACTION_GOTOCLIP),
                                 "Shift-G", "Goto clipboard EA/name", 0),
            idaapi.action_desc_t(ACTION_COPYNAME, "Copy highligh name", hotkey_action_handler_t(ACTION_COPYNAME),
                                 "Shift-C", "Copy current highlight full name to clipboard", 0),
            idaapi.action_desc_t(ACTION_PASTENAME, "Paste to highligh name", hotkey_action_handler_t(ACTION_PASTENAME),
                                 "Shift-V", "Paste clipboard text to current highlight name", 0),
        )
        for action in hotkey_actions:
            idaapi.register_action(action)
            self.registered_actions.append(action.name)

        # Add ui hook
        self.ui_hook = UI_Hook()
        self.ui_hook.hook()

        # Add hexrays ui callback
        if idaapi.init_hexrays_plugin():
            addon = idaapi.addon_info_t()
            addon.id = "tw.l4ys.lazyida"
            addon.name = "LazyIDA"
            addon.producer = "Lays, HTC - VinCSS"
            addon.url = "https://github.com/L4ys/LazyIDA"
            addon.version = "1.0.0.4"
            idaapi.register_addon(addon)

            hx_actions = (
                idaapi.action_desc_t(ACTION_HX_REMOVERETTYPE, "Remove return type", hexrays_action_handler_t(ACTION_HX_REMOVERETTYPE), "v"),
                idaapi.action_desc_t(ACTION_HX_COPYEA, "Copy ea", hexrays_action_handler_t(ACTION_HX_COPYEA), "w"),
                idaapi.action_desc_t(ACTION_HX_COPYNAME, "Copy name", hexrays_action_handler_t(ACTION_HX_COPYNAME), "Shift-C"),
                idaapi.action_desc_t(ACTION_HX_PASTENAME, "Paste name", hexrays_action_handler_t(ACTION_HX_PASTENAME), "Shift-V"),
                idaapi.action_desc_t(ACTION_HX_GOTOCLIP, "Goto clipboard ea", hexrays_action_handler_t(ACTION_HX_GOTOCLIP), "Shift-G"),
            )
            for action in hx_actions:
                idaapi.register_action(action)
                self.registered_hx_actions.append(action.name)

            self.hx_hook = HexRays_Hook()
            idaapi.install_hexrays_callback(self.hx_hook.callback)
            self.hexrays_inited = True

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if hasattr(self, "ui_hook"):
            self.ui_hook.unhook()

        # Unregister actions
        for action in self.registered_actions:
            idaapi.unregister_action(action)

        if self.hexrays_inited:
            # Unregister hexrays actions
            for action in self.registered_hx_actions:
                idaapi.unregister_action(action)
            if self.hx_hook:
                idaapi.remove_hexrays_callback(self.hx_hook.callback)
            idaapi.term_hexrays_plugin()

        print("[LazyIDA] plugin terminated.")


def PLUGIN_ENTRY():
    return LazyIDA_t()
