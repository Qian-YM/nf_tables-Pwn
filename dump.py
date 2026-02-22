import gdb

class kmalloc(gdb.Command):
    """在断点触发时打印所有寄存器"""

    def __init__(self):
        super(kmalloc, self).__init__("kmalloc", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if "0x" in arg:
            arg = int(arg, 16)
        else:
            arg = int(arg)
        offset = 0
        if arg == 96:
            offset = 8
        elif arg == 192:
            offset = 16
        else:
            offset = 0
            while True:
                if 2 ** offset == arg:
                    break
                offset += 1
            #print("offset == ", offset)  
            offset *= 8
        o = gdb.execute("p &kmalloc_caches", to_string=True)
        print(o)
        o = o[o.find("0x"):o.find("0x")+18]
        kmalloc_caches = int(o, 16)
        cmd = f"tele 0x{(kmalloc_caches+offset):x}"
        o = gdb.execute(cmd, to_string=True)
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):o.find("0x")+18]
        kmem_cache = int(o, 16)
        gs_base = gdb.execute("info r gs_base", to_string=True)
        gs_base = gs_base[gs_base.find("0x"):gs_base.find("0x")+18]
        gs_base = int(gs_base, 16)
        o = gdb.execute(f"tele 0x{kmem_cache:x}", to_string=True)
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):o.find("\n")]
        cpu_offset = int(o, 16)
        print(f"gs_base == 0x{gs_base:x}, cpu_offset == 0x{cpu_offset:x}")
        kmem_cache_cpu = gs_base + cpu_offset
        gdb.execute(f"p *(struct kmem_cache *) 0x{kmem_cache:x}")
        gdb.execute(f"p *(struct kmem_cache_cpu *) 0x{kmem_cache_cpu:x}")

class dump_list(gdb.Command):
    """在断点触发时打印所有寄存器"""

    def __init__(self):
        super(dump_list, self).__init__("dump_list", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if "0x" in arg:
            arg = int(arg, 16)
        else:
            arg = int(arg)
        offset = 0
        if arg == 96:
            offset = 8
        elif arg == 192:
            offset = 16
        else:
            offset = 0
            while True:
                if 2 ** offset == arg:
                    break
                offset += 1
            #print("offset == ", offset)  
            offset *= 8
        o = gdb.execute("p &kmalloc_caches", to_string=True)
        print(o)
        o = o[o.find("0x"):o.find("0x")+18]
        kmalloc_caches = int(o, 16)
        cmd = f"tele 0x{(kmalloc_caches+offset):x}"
        o = gdb.execute(cmd, to_string=True)
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):o.find("0x")+18]
        kmem_cache = int(o, 16)
        gs_base = gdb.execute("info r gs_base", to_string=True)
        gs_base = gs_base[gs_base.find("0x"):gs_base.find("0x")+18]
        gs_base = int(gs_base, 16)
        o = gdb.execute(f"tele 0x{kmem_cache:x}", to_string=True)
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):o.find("\n")]
        cpu_offset = int(o, 16)
        print(f"gs_base == 0x{gs_base:x}, cpu_offset == 0x{cpu_offset:x}")
        kmem_cache_cpu = gs_base + cpu_offset
        #gdb.execute(f"p *(struct kmem_cache *) 0x{kmem_cache:x}")
        o = gdb.execute(f"p *(struct kmem_cache_cpu *) 0x{kmem_cache_cpu:x}", to_string= True)
        o = o[o.find("freelist"):]
        o = o[:o.find("\n")]
        o = o[o.find("0x"):o.find("0x")+18]
        addr = int(o, 16)
        o = gdb.execute(f"p *(struct kmem_cache *) 0x{kmem_cache:x}", to_string=True)
        o = o[o.find("offset"):]
        o = o[:o.find("\n")]
        o = o[o.find("= ")+2:o.find(",")]
        off = int(o)
        
        while addr:
            print(f"obj : 0x{addr:x}")
            o = gdb.execute(f"tele 0x{(addr+off):x}", to_string=True)
            o = o[:o.find("\n")]
            o = o[o.find("0x")+2:]
            o = o[o.find("0x"):o.find("0x")+18]
            if "0x0 <fixed_percpu_" == o:
                addr = 0
                break
            addr = int(o, 16)
            
class kmem_cache(gdb.Command):
    def __init__(self):
        self.slab_cache_offset = 0x18
        self.name_offset = 0x60
        self.slab_next_offset = 0x8
        super(kmem_cache, self).__init__("kmem_cache", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        #print(arg)
        addr = int(arg, 16)
        self.get_kmem_cache(addr)
    def get_kmem_cache(self, addr:int)->str:
        page = addr - (addr & 0xfff)
        page_offset = (page - 0xffff888000000000) // 0x1000
        page_struct = 0xffffea0000000000 + page_offset * 0x40
        o = gdb.execute(f"tele 0x{(page_struct+self.slab_next_offset):x}", to_string=True)
        o = o[:o.find("\n")]
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):]
        o = o[0:18]
        next = int(o, 16)
        print("next ==", hex(next))
        if next&1 == 1:
            page_struct = next - 1
        o = gdb.execute(f"tele 0x{(page_struct+self.slab_cache_offset):x}", to_string=True)
        o = o[:o.find("\n")]
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):]
        o = o[0:18]
        kmem_cache_addr = int(o, 16)
        o = gdb.execute(f"tele 0x{(kmem_cache_addr+self.name_offset):x}", to_string=True)
        o = o[:o.find("\n")]
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):]
        o = o[0:18]
        name_addr = int(o, 16)
        o = gdb.execute(f"tele 0x{name_addr:x}", to_string=True)
        o = o[o.find("'")+1:o.find("\n")]
        o = o[:o.find("'")]
        print(o)
        return o

class gs_base(gdb.Command):
    def __init__(self):
        super(gs_base, self).__init__("gs_base", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        o = gdb.execute(f"info r gs_base", to_string=True)
        o = o[o.find("0x"):][0:18]
        gs_base = int(o, 16)
        print(o)

class current_task(gdb.Command):
    def __init__(self):
        super(current_task, self).__init__("current_task", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        gs_base = gdb.execute(f"gs_base", to_string=True)
        gs_base = int(gs_base, 16)
        o = gdb.execute(f"p &current_task", to_string=True)
        o = o[o.find("0x"):]
        o = o[:o.find(" ")]
        offset = int(o, 16)
        task = gs_base + offset
        gdb.execute(f"tele 0x{task:x}")

class buddy(gdb.Command):
    def __init__(self):
        super(buddy, self).__init__("buddy", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        o = gdb.execute(f"p &node_data", to_string=True)
        o = o[o.find("0x"):][0:18]
        node_data = int(o, 16)
        for i in range(0, 0x100, 8):
            o = gdb.execute(f"x/g 0x{(node_data+i):x}", to_string=True)
            o = o[o.find("0x")+2:]
            o = o[o.find("0x"):][0:18] 
            node = int(o, 16)
            #print(hex(node))
            if node == 0:
                break
            self.dump_node(node)
    def dump_node(self, node:int):
        o = gdb.execute(f"p (*(struct pglist_data *)0x{node:x}).nr_zones", to_string=True)
        nr_zones = int(o[o.find("=")+2:])
        #print(f"nr_zones == {nr_zones}") 
        for i in range(nr_zones):
            o = gdb.execute(f"info r gs_base", to_string=True)
            o = o[o.find("0x"):][0:18]
            gs_base = int(o, 16)
            o = gdb.execute(f"p (*(struct pglist_data *)0x{node:x}).node_zones[{i}].per_cpu_pageset", to_string=True)
            o = o[o.find("0x"):]
            cpu_page_set = gs_base + int(o, 16)
            #print(f"cpu_page_set == 0x{cpu_page_set:x}")
            o = gdb.execute(f"p (*(struct per_cpu_pages *)0x{cpu_page_set:x}).count", to_string=True)
            count = int(o[o.find("=")+2:])
            print(f"zone:{i}, per_cpu_pages:{count}")

            for j in range(11):
                o = gdb.execute(f"p (*(struct pglist_data *)0x{node:x}).node_zones[{i}].free_area[{j}].nr_free", to_string=True)
                nr_free = int(o[o.find("=")+2:])
                if nr_free == 0:
                    continue
                print(f"zone:{i}, order:{j}, nr_free:{nr_free}")

class dump_page(gdb.Command):
    def __init__(self):
        super(dump_page, self).__init__("dump_page", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        args = arg.split(' ')
        if len(args) != 3:
            print("usage : dump_page [node] [zone] [order]")
            return 
        node = int(args[0])
        zone = int(args[1])
        order = int(args[2])
        o = gdb.execute(f"p &node_data", to_string=True)
        o = o[o.find("0x"):][0:18]
        node_data = int(o, 16)
        o = gdb.execute(f"x/g 0x{(node_data+node*8):x}", to_string=True)
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):][0:18] 
        node = int(o, 16)
        if node == 0:
            print("bad node idx")
            return
        for i in range(4):
            o = gdb.execute(f"p (*(struct pglist_data *)0x{node:x}).node_zones[{zone}].free_area[{order}].free_list[{i}].prev", to_string=True)
            o = o[o.find("0x"):][0:18]
            next = int(o, 16)
            if next&0xffffff0000000000 != 0xffffea0000000000:
                continue
            print("migrate type : ", i)
            while 1:
                page = (next&0xffffffff)//0x40*0x1000 + 0xffff888000000000
                print(f"0x{next:x} -> 0x{page:x}")
                o = gdb.execute(f"p (*(struct page *)0x{next:x}).lru.next", to_string=True)
                o = o[o.find("0x"):][0:18] 
                next = int(o, 16)
                if next&0xffffff0000000000 != 0xffffea0000000000:
                    break

class dump_cpu_page(gdb.Command):
    def __init__(self):
        super(dump_cpu_page, self).__init__("dump_cpu_page", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        args = arg.split(" ")
        if len(args) != 2:
            print("usage : dump_page [node] [zone]")
            return 
        node = int(args[0])
        zone = int(args[1])
        o = gdb.execute(f"p &node_data", to_string=True)
        o = o[o.find("0x"):][0:18]
        node_data = int(o, 16)
        o = gdb.execute(f"x/g 0x{(node_data+node*8):x}", to_string=True)
        o = o[o.find("0x")+2:]
        o = o[o.find("0x"):][0:18] 
        node = int(o, 16)
        #print(f"node == 0x{node:x}")
        o = gdb.execute(f"info r gs_base", to_string=True)
        o = o[o.find("0x"):][0:18]
        gs_base = int(o, 16)
        o = gdb.execute(f"p (*(struct pglist_data *)0x{node:x}).node_zones[{zone}].per_cpu_pageset", to_string=True)
        o = o[o.find("0x"):]
        cpu_page_set = gs_base + int(o, 16)
        for i in range(12):
            o = gdb.execute(f"p (*(struct per_cpu_pages *)0x{cpu_page_set:x}).lists[{i}].prev", to_string=True)
            o = o[o.find("0x"):][0:18]
            next = int(o, 16)
            if next&0xffffff0000000000 != 0xffffea0000000000:
                continue
            print("migrate type : ", i)
            while 1:
                page = (next&0xffffffff)//0x40*0x1000 + 0xffff888000000000
                print(f"0x{next:x} -> 0x{page:x}")
                o = gdb.execute(f"p (*(struct page *)0x{next:x}).lru.next", to_string=True)
                o = o[o.find("0x"):][0:18] 
                next = int(o, 16)
                if next&0xffffff0000000000 != 0xffffea0000000000:
                    break




kmalloc()
dump_list()
kmem_cache()
gs_base()
current_task()
buddy()
dump_page()
dump_cpu_page()