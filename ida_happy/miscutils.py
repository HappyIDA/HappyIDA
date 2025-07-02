import ida_typeinf
import ida_lines

def info(msg):
    print(f'[HappyIDA] {msg}')

def error(msg):
    print(f'[HappyIDA] Error: {msg}')

def parse_type(tif, typename):
    typename += " ;"
    # we have to distinguish None from empty string, since parse_decl returns the parsed variable name
    if ida_typeinf.parse_decl(tif, ida_typeinf.get_idati(), typename, ida_typeinf.PT_SIL) == None:
        error(f"Unable to parse declaration: {typename}")
        return False

    return True

def tag_text(text, tag):
    # address tagging doesn't have COLOR_OFF pair
    FMT = '%c%c%' + '0%dX' % ida_lines.COLOR_ADDR_SIZE + '%s'
    return FMT % (ida_lines.COLOR_ON, ida_lines.COLOR_ADDR, tag, text)