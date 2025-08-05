import idaapi
import ida_hexrays
import ida_kernwin
import ida_tryblks
import ida_range
import re
from ida_happy.miscutils import info, error

def traverse_blocks(blocks):
    # always skip entry block and exit block
    cur = blocks.nextb
    while cur.start != idaapi.BADADDR:
        yield cur
        cur = cur.nextb

class HexraysRebuildSEHHook(ida_hexrays.Hexrays_Hooks):
    """rebuild the missing SEH try except statements"""
    def __init__(self):
        super().__init__()
        self.seh_list = []
        self.banned_set = set()
        self.notify_user = False

    def prolog(self, mba, fc, reachable_blocks, decomp_flags):
        self.seh_list = []
        self.notify_user = False
        self.gather_seh_info(mba, fc, reachable_blocks)
        return 0

    def microcode(self, mba):
        self.insert_catch_block(mba)
        return 0

    def maturity(self, cfunc, maturity):
        if maturity == idaapi.CMAT_FINAL:
            self.mutate_ctree(cfunc)
        return 0

    def func_printed(self, cfunc):
        self.annotate_seh(cfunc)

        if self.notify_user:
            ida_kernwin.warning('Unable to correctly decompile some try blocks, press "F5" again to resolve it.')
        return 0

    def gather_seh_info(self, mba, fc, reachable_blocks):
        func = idaapi.get_func(mba.entry_ea)

        tbks = ida_tryblks.tryblks_t()
        r = ida_range.range_t(func.start_ea, func.end_ea)
        ida_tryblks.get_tryblks(tbks, r)

        blk_idx_map = {}

        for i in range(fc.size()):
            blk_idx_map[fc[i].start_ea] = i

        for idx, tryblock in enumerate(tbks):
            # skip block 0 (it covers the function itself)
            # skip cpp seh
            if not idx or not tryblock.is_seh():
                continue

            # TODO: should consider nested SEH case
            # TODO: could contain multiple ranges (nested case?), should check if len > 1
            # finally block?
            rge = tryblock[0]
            try_start = rge.start_ea
            try_end = rge.end_ea

            if try_start in self.banned_set:
                info(f'ignore try block @ {hex(try_start)}')
                continue

            eh_start_list = []
            for eh in tryblock.seh():
                # since some unreachable catch blocks are never included in the microcode block list,
                # we have to restore all blocks reachable from the catch block in bitmap

                # initialize the list with catch block index
                blocks = [blk_idx_map[eh.start_ea]]

                # traverse all blocks from catch block
                while len(blocks):
                    block_idx = blocks.pop()
                    if not reachable_blocks.has(block_idx):
                        # info(f'restore unreferenced block #{block_idx}')
                        reachable_blocks.add(block_idx)
                        # push all successors into list
                        for i in range(fc.nsucc(block_idx)):
                            blocks.append(fc.succ(block_idx, i))

                eh_start_list.append(eh.start_ea)

            # print(f'try block #{idx}')
            # print(f'range: [{hex(try_start)}, {hex(try_end)}) -> {[hex(i) for i in eh_start_list]}')

            # NOTE: currently support only one catch block
            # also, it looks like msvc only accept one __except block?
            self.seh_list.append((try_start, try_end, eh_start_list[0]))

    def insert_catch_block(self, mba: ida_hexrays.mba_t):
        func = idaapi.get_func(mba.entry_ea)
        tbks = ida_tryblks.tryblks_t()

        r = ida_range.range_t(func.start_ea, func.end_ea)
        ida_tryblks.get_tryblks(tbks, r)

        bb_start_map = {}
        for block in traverse_blocks(mba.blocks):
            bb_start_map[block.start] = block

        # add multiple new block
        # insert jz to reference catch block in decompiler generated ctree
        for try_start, try_end, eh_start in self.seh_list:
            try_bk = bb_start_map[try_start]
            eh_bk = bb_start_map[eh_start]

            # this will auto update all the block numbers including eh_bk.serial
            blk = mba.insert_block(try_bk.serial)
            blk.start = try_start
            blk.end = try_start + 1

            # jnz [0x41414141], 0, @eh_idx
            l = ida_hexrays.mop_t()
            r = ida_hexrays.mop_t()
            d = ida_hexrays.mop_t()

            # 1 byte global variable @ 0x41414141
            l.t = idaapi.mop_v
            l.g = 0x41414141
            l.size = 1
            # 1 byte constant 0
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

    def mutate_ctree(self, cfunc: ida_hexrays.cfunc_t):
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
        # TODO: control flow can actually jump between different try block region,
        # so each block in the try block should be handled differently.
        # currently I have no idea to resolve this...
        body = cfunc.body
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
                # TODO: we *should* consider the inverted case (if (![0x41414141]){...})
                if not it.is_expr() \
                   and it.op == idaapi.cit_if \
                   and it.cinsn.cif.expr.op == idaapi.cot_obj \
                   and it.cinsn.cif.expr.obj_ea == 0x41414141:
                    break
                it = body.find_parent_of(it)
            else:
                self.notify_user = True
                self.banned_set.add(try_start)
                error(f'Failed to find valid catch block @ {hex(try_start)}')
                continue

            cur_insn = it.cinsn
            cif = cur_insn.cif

            def next_insn_iter(body, insn):
                # it needs to be cinsn_t to make below compare works
                assert(type(insn) == ida_hexrays.cinsn_t)

                pi = body.find_parent_of(insn).cinsn
                assert(pi.op == ida_hexrays.cit_block)

                blk_iter = pi.cblock.begin()
                while blk_iter != pi.cblock.end():
                    if blk_iter.cur == insn:
                        break
                    next(blk_iter)
                else:
                    raise Exception('unable to get the iterator of current insn')

                next(blk_iter)
                return blk_iter, blk_iter == pi.cblock.end()

            if cif.ielse:
                else_block = cif.ielse.cblock
                # If the else block not only contains try block, directly move them out of else block will
                # produce wrong semantics. To fix this, we construct a goto insn in catch block to correct
                # the semantics after the ctree transformation
                # handle: if (...) { CATCH... } else { TRY...; OTHERS; }
                # into:   if (...) { CATCH...; goto L1; } else { TRY...; OTHERS; } L1: ...
                if not all(try_start <= ins.ea < try_end for ins in else_block):
                    it = cur_insn
                    insert_continue = False

                    while True:
                        next_iter, is_end = next_insn_iter(body, it)
                        if not is_end:
                            break

                        it = body.find_parent_of(it).cinsn # cblock
                        it = body.find_parent_of(it)
                        # if we traversed to the outermost cblock
                        if it == None:
                            break

                        it = it.cinsn # cif, cfor, cwhile, cdo, cswitch
                        if it.op == ida_hexrays.cit_if:
                            continue

                        # if end-of-block is reached, for while/for/do we can just emit a continue
                        if it.op in [ida_hexrays.cit_while, ida_hexrays.cit_for, ida_hexrays.cit_do]:
                            insert_continue = True
                            break

                        # NOTE: no good enough way to deal with cswitch
                        self.notify_user = True
                        self.banned_set.add(try_start)
                        error(f'Cannot handle try block @ {hex(try_start)}')
                        return False

                    if it == None:
                        # no need to fix anything, the else block definitely ends in return/goto
                        pass

                    elif insert_continue:
                        # build a continue insn to correct the semantics
                        catch_block = cif.ithen.cblock
                        last_insn = catch_block.back()
                        insn = ida_hexrays.cinsn_t()
                        insn.op = ida_hexrays.cit_continue
                        insn.ea = last_insn.ea

                        # insert continue into catch block
                        next_it, _ = next_insn_iter(body, last_insn)
                        pi = body.find_parent_of(last_insn).cinsn
                        pi.cblock.insert(next_it, insn)

                    else:
                        # insert goto
                        # if no label_num assigned, assign it (must be its mblock serial)
                        next_it = next_iter.cur.cinsn
                        if next_it.label_num == -1:
                            for mblock in traverse_blocks(cfunc.mba.blocks):
                                if mblock.start <= next_it.ea < mblock.end:
                                    next_it.label_num = mblock.serial
                                    break
                            else:
                                error(f'cannot find corresponding mblock @ {hex(next_it.ea)}')
                                return False

                        label_num = next_it.label_num

                        # build a goto insn to correct the semantics
                        catch_block = cif.ithen.cblock
                        last_insn = catch_block.back()
                        insn = ida_hexrays.cinsn_t()
                        insn.op = ida_hexrays.cit_goto
                        insn.ea = last_insn.ea
                        insn.cgoto = ida_hexrays.cgoto_t()
                        insn.cgoto.label_num = label_num

                        # insert goto into catch block
                        next_iter, _ = next_insn_iter(body, last_insn)
                        pi = body.find_parent_of(last_insn).cinsn
                        pi.cblock.insert(next_iter, insn)

                # transform: if (...) { A... } else { B... }
                # into: if (...) { A... } B...
                # move all else block insn one block above
                next_iter, _ = next_insn_iter(body, cur_insn)

                # NOTE: might need to handle label_num of the else block
                pi = body.find_parent_of(cur_insn).cinsn
                while else_block.begin() != else_block.end():
                    insn = ida_hexrays.cinsn_t()
                    insn.swap(else_block.begin().cur)
                    else_block.erase(else_block.begin())
                    pi.cblock.insert(next_iter, insn)

            # cherry pick the catch block out of the ctree
            insn = ida_hexrays.cinsn_t()
            insn.swap(cif.ithen)
            insn.ea = eh_start

            # NOTE: important step here, otherwise pop INTERR 50728
            if cur_insn.contains_label() and insn.contains_label():
                # TODO: this could still cause INTERR if ithen & ielse both contain label
                error('IDA should crash in second')

            elif cur_insn.contains_label():
                # create a block inst (because it won't get printed) to hold label
                empty_block = ida_hexrays.cblock_t()
                empty_insn = ida_hexrays.cinsn_t()
                empty_insn.op = idaapi.cit_block
                empty_insn.cblock = empty_block
                empty_insn.ea = cur_insn.ea
                empty_insn.label_num = cur_insn.label_num
                cur_insn.swap(empty_insn)

            else:
                # we can safely delete if statement
                pit = body.find_parent_of(cur_insn).cinsn
                assert(pit.op == idaapi.cit_block)

                it = pit.cblock.begin()
                while it != pit.cblock.end():
                    if it.cur == cur_insn:
                        pit.cblock.erase(it)
                        break
                    next(it)
                else:
                    error('failed to delete if statement')
                    return False

            # NOTE: we cannot set ea to arbitrary insn: cif_t requires it.ea == it.cif.expr.ea
            # workaround for `if ([0x41414141]) break;`
            # cur_insn.cblock[0].ea = eh_start # causing INTERR 50683
            insn_map[try_start] = insn

        # the second search will yield the actual try block (currently just an expr),
        # since we just delete the preceding if statement
        for try_start, try_end, eh_start in self.seh_list:
            # TODO: should remove this after the issue resolved
            if try_start not in insn_map:
                continue

            # different from the catch block case where the if statement must locate at the try_start,
            # here we might find a insn not actually locate inside try block, so some adjustment must be made
            search_start = try_start
            while True:
                it = body.find_closest_addr(search_start)
                if it.ea >= try_start:
                    break
                search_start += 1

            # find the start insn of the new try block
            while it.is_expr():
                it = body.find_parent_of(it)

            # NOTE: find_parent_of may return a block if the try block starts exactly at the start of a block
            # use the first instruction of the block as the start of the try block
            # an exception of this is when it select the placeholder empty block which used for holding label
            if it.op == idaapi.cit_block and len(it.cinsn.cblock) > 0:
                pi = it.cinsn
                it = it.cinsn.cblock[0]
                cur_insn = it.cinsn
            else:
                cur_insn = it.cinsn
                pi = body.find_parent_of(it).cinsn

            assert(pi.op == idaapi.cit_block)

            # find the start and end index of the try block inside the outer block
            start_idx = 0
            while pi.cblock[start_idx] != cur_insn:
                start_idx += 1

            for end_idx in range(start_idx, pi.cblock.size()):
                if pi.cblock[end_idx].ea >= try_end:
                    break
            else:
                end_idx += 1

            # build & insert try block
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
            pi.cblock.insert(it, try_insn)

            # insert catch block below the try block
            catch_insn = insn_map[try_start]
            pi.cblock.insert(it, catch_insn)

            # NOTE: the type of splice binding is flawed... (qlist< cinsn_t >::iterator v.s. cinsn_list_t_iterator)
            # cblock.splice(cblock, pi.cblock, start_ptr, end_ptr)
            del insn_map[try_start]

        if insn_map:
            error('Failed to find all try blocks')

    def annotate_seh(self, cfunc: ida_hexrays.cfunc_t):
        ccode = cfunc.get_pseudocode()
        try_set = set(try_start for try_start, _, _ in self.seh_list)
        eh_set = set(eh_start for _, _, eh_start in self.seh_list)

        for i in range(len(cfunc.treeitems)):
            insn = cfunc.treeitems[i]
            if insn.op == ida_hexrays.cit_block and insn.ea in try_set:
                # avoid the case when both if/else/for/while/do block and try block occupy the same address
                pit = cfunc.body.find_parent_of(insn)
                if pit and pit.cinsn.op != ida_hexrays.cit_block:
                    continue

                try_insn = insn.cinsn
                x, y = cfunc.find_item_coords(try_insn)
                ccode[y].line = ccode[y].line.replace('{', '__try {')

            elif insn.op == ida_hexrays.cit_block and insn.ea in eh_set:
                try_insn = insn.cinsn
                x, y = cfunc.find_item_coords(try_insn)
                if '{' in ccode[y].line:
                    ccode[y].line = ccode[y].line.replace('{', '__except(...) {')
                else:
                    # workaround to handle oneline return & break (maybe continue?)
                    # since it will not contain the `{ ... }` syntax
                    matched = re.match('(.*)(return|break|continue|goto)(.*)', ccode[y].line)
                    if not matched:
                        error('failed to find exception code block')
                        continue
                    ccode[y].line = matched[1] + '__except(...) { ' + matched[2] + matched[3] + ' }'
