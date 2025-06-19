import idaapi
import ida_hexrays
import ida_tryblks
import ida_range

class HexraysRebuildSEHHook(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        super().__init__()
        self.seh_list = []

    def prolog(self, mba, fc, reachable_blocks, decomp_flags):
        self.seh_list = []
        self.gather_seh_info(mba, reachable_blocks)
        return 0

    def microcode(self, mba):
        self.insert_catch_block(mba)
        return 0

    def maturity(self, cfunc, maturity):
        if maturity == idaapi.CMAT_FINAL:
            self.mutate_ctree(cfunc.body)
        return 0

    def func_printed(self, cfunc):
        self.annotate_seh(cfunc)
        return 0

    def gather_seh_info(self, mba, reachable_blocks):
        func = idaapi.get_func(mba.entry_ea)

        tbks = ida_tryblks.tryblks_t()
        r = ida_range.range_t(func.start_ea, func.end_ea)
        ida_tryblks.get_tryblks(tbks, r)

        for idx, tryblock in enumerate(tbks):
            # skip block 0 (it covers the function itself)
            # skip cpp seh
            if not idx or not tryblock.is_seh():
                continue

            print(f'try block #{idx}')
            # TODO: should consider nested SEH case
            # TODO: could contain multiple ranges (nested case?), should check if len > 1
            # finally block?
            rge = tryblock[0]
            try_start = rge.start_ea
            try_end = rge.end_ea

            # some unreachable catch blocks never be included in the microcode block list,
            # not all because it's judged by bitmap
            # add it back here
            eh_start_list = []
            for eh in tryblock.seh():
                # NOTE: the const 25 here just somehow guessed, does not reference any public hexrays docs
                block_bit = ((eh.start_ea - mba.entry_ea) // 25) + 1
                if not reachable_blocks.has(block_bit):
                    print('encounter not generated eh block at', hex(eh.start_ea))
                    reachable_blocks.add(block_bit)

                eh_start_list.append(eh.start_ea)

            print(f'range: [{hex(try_start)}, {hex(try_end)})')
            print(f'handler: {[hex(i) for i in eh_start_list]}')

            # TODO: currently support only one catch block
            # however, it looks like msvc only accept one __except block?
            self.seh_list.append((try_start, try_end, eh_start_list[0]))

    def insert_catch_block(self, mba: ida_hexrays.mba_t):
        func = idaapi.get_func(mba.entry_ea)
        tbks = ida_tryblks.tryblks_t()

        r = ida_range.range_t(func.start_ea, func.end_ea)
        ida_tryblks.get_tryblks(tbks, r)

        def traverse_blocks(blocks):
            # always skip entry block and exit block
            cur = blocks.nextb
            while cur.start != idaapi.BADADDR:
                yield cur
                cur = cur.nextb

        bb_start_map = {}
        for block in traverse_blocks(mba.blocks):
            bb_start_map[block.start] = block

        # add multiple new block
        # insert jz to reference catch block in decompiler generated ctree
        for try_start, try_end, eh_start in self.seh_list:
            try_bk = bb_start_map[try_start]
            eh_bk = bb_start_map[eh_start]

            # this will auto update all the block numbers
            blk = mba.insert_block(try_bk.serial)
            blk.start = try_start
            blk.end = try_start + 1

            # jz [0x41414141], 0x69, @eh_idx
            l = ida_hexrays.mop_t()
            r = ida_hexrays.mop_t()
            d = ida_hexrays.mop_t()

            # 1 byte global variable @ 0x41414141
            l.t = idaapi.mop_v
            l.g = 0x41414141
            l.size = 1
            # 1 byte constant 0x69
            r.make_number(0, 1)
            # reference to block #eh_bk
            d.make_blkref(eh_bk.serial)

            # map to try_start to ease the search during next stage
            insn = ida_hexrays.minsn_t(try_start)
            insn.opcode = idaapi.m_jnz
            insn.l = l
            insn.r = r
            insn.d = d
            blk.insert_into_block(insn, blk.tail)

    def mutate_ctree(self, body):
        # transform:
        # ```
        # if (ADDR[0x41414141]) { ... except block }
        # ...
        # { ... try block }
        # ```
        # into:
        # ```
        # { ... try block }
        # { ... except block }
        # ```
        insn_map = {}
        # find_closest_addr and find_parent_of will re-iterate the ctree,
        # so it's safe to mutate the tree in the loop

        def block_iter(block, idx):
            cur = block.begin()
            while idx:
                next(cur)
                idx -= 1
            return cur

        # the first search will give us the catch block, which is inserted at the same address
        # but precedes the try block in block order
        for try_start, try_end, eh_start in self.seh_list:
            it = body.find_closest_addr(try_start)
            while it:
                if not it.is_expr() \
                   and it.op == idaapi.cit_if \
                   and it.cinsn.cif.expr.op == idaapi.cot_obj \
                   and it.cinsn.cif.expr.obj_ea == 0x41414141:
                    break
                it = body.find_parent_of(it)
            else:
                raise Exception('Failed to find valid catch block')

            cur_insn = it.cinsn
            cif = cur_insn.cif
            # NOTE: should we consider the inverted case? (if (![0x41414141]){...})
            # if else branch exists, move the contents (contains try, and maybe other blocks) out of the if block
            if cif.ielse:
                else_block = cif.ielse.cblock

                pi = body.find_parent_of(it).cinsn
                assert(pi.op == ida_hexrays.cit_block)

                blk_iter = pi.cblock.begin()
                while blk_iter != pi.cblock.end():
                    if blk_iter.cur == cur_insn:
                        break
                    next(blk_iter)

                next(blk_iter)
                while else_block.begin() != else_block.end():
                    insn = ida_hexrays.cinsn_t()
                    insn.swap(else_block.begin().cur)
                    else_block.erase(else_block.begin())
                    pi.cblock.insert(blk_iter, insn)

            # swap out the insn(cblock_t) from if.then to move it up by one level
            insn = ida_hexrays.cinsn_t()
            insn.swap(cif.ithen)
            cur_insn.swap(insn)
            cur_insn.ea = eh_start

            # record the iterator of the catch block in its parent block
            pi = body.find_parent_of(it).cinsn
            assert(pi.op == ida_hexrays.cit_block)
            blk_iter = pi.cblock.begin()
            while blk_iter != pi.cblock.end():
                if blk_iter.cur == cur_insn:
                    insn_map[try_start] = (pi, blk_iter)
                    break
                next(blk_iter)
            else:
                raise Exception('Failed to get previous block iterator')

        # the second search will yield the actual try blocks,
        # since we just delete the preceding if statement
        for try_start, try_end, eh_start in self.seh_list:
            it = body.find_closest_addr(try_start)
            while it.is_expr():
                it = body.find_parent_of(it)

            cur_insn = it.cinsn
            pi = body.find_parent_of(it).cinsn
            assert(pi.op == ida_hexrays.cit_block)

            if pi.op == idaapi.cit_block:
                start_idx = 0
                while pi.cblock[start_idx] != cur_insn:
                    start_idx += 1

                for end_idx in range(start_idx, pi.cblock.size()):
                    if pi.cblock[end_idx].ea >= try_end:
                        break
                else:
                    end_idx += 1

                try_block = ida_hexrays.cblock_t()
                try_insn = ida_hexrays.cinsn_t()
                try_insn.op = idaapi.cit_block
                try_insn.cblock = try_block
                # NOTE: important step here, otherwise pop INTERR 50681
                # plugins/hexrays_sdk/verifier/cverify.cpp
                try_insn.ea = try_start

                for idx in range(start_idx, end_idx):
                    # NOTE: we cannot do this because the erase operation will always free the object
                    # instead, using swap to take out the insn obj
                    # try_block.push_back(pi.cblock[idx])
                    new_insn = ida_hexrays.cinsn_t()
                    new_insn.swap(pi.cblock[idx])
                    try_block.push_back(new_insn)

                for _ in range(end_idx - start_idx):
                    # no way to duplicate a iterator...
                    it = block_iter(pi.cblock, start_idx)
                    pi.cblock.erase(it)

                it = block_iter(pi.cblock, start_idx)
                # TODO: no need to assign + next(it), just insert
                it = pi.cblock.insert(it, try_insn)

                # move catch block below the try block (swap it out first)
                # be caution: cpi could equal to pi
                cpi, cit = insn_map[try_start]
                catch_insn = ida_hexrays.cinsn_t()
                catch_insn.swap(cit.cur)
                # TODO: fix this, cpi.cblock could be None
                cpi.cblock.erase(cit)

                next(it)
                pi.cblock.insert(it, catch_insn)

                # NOTE: the type of splice binding is flawed... (qlist< cinsn_t >::iterator v.s. cinsn_list_t_iterator)
                # cblock.splice(cblock, pi.cblock, start_ptr, end_ptr)
                del insn_map[try_start]
            else:
                # matched something else
                print('WTF')

        if insn_map:
            raise Exception('Failed to find all try blocks')

    def annotate_seh(self, cfunc):
        ccode = cfunc.get_pseudocode()
        try_set = set(try_start for try_start, _, _ in self.seh_list)
        eh_set = set(eh_start for _, _, eh_start in self.seh_list)

        for i in range(len(cfunc.treeitems)):
            insn = cfunc.treeitems[i]
            if insn.op == ida_hexrays.cit_block and insn.ea in try_set:
                try_insn = cfunc.treeitems[i].cinsn
                x, y = cfunc.find_item_coords(try_insn)
                ccode[y].line = ccode[y].line.replace('{', '__try {')

            elif insn.op == ida_hexrays.cit_block and insn.ea in eh_set:
                try_insn = cfunc.treeitems[i].cinsn
                x, y = cfunc.find_item_coords(try_insn)
                ccode[y].line = ccode[y].line.replace('{', '__except(...) {')
