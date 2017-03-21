import numpy as np
#initialize main memory here
class memory:
	def __init__(self):
		self.main_mem = self.make_mem()

	def make_mem(self):
		array = range(0, 0xff + 0x1)
		lol_main_memory = []
		for i in range(8):
			lol_main_memory.append(array)
		main_memory = sum(lol_main_memory, [])
		return main_memory

	def get_block(self, block_begin_addr):
		return self.main_mem[block_begin_addr : block_begin_addr + 0xf + 1]


class cache_row:
	def __init__(self, slot):
		self.slot = slot
		self.hit = 0
		self.tag = 0
		self.data = [0] * 16
	# def __repr__(self):
	# 	return "%s    %s     %s     %s"  % (self.slot, self.hit, self.tag, self.data)

	def check_hit(self):
		if self.hit == 1:
			return True
		if self.hit == 0:
			return False

	def change_hit(self):
		self.hit = 1

	def check_tag(self, tag):
		if self.tag == tag:
			return True
		else:
			return False

	def update_tag(self, tag):
		self.tag = tag

	def update_data(self, data):
		self.data = data


def parse_address(address):
	slot_num = (address & 0x00f0)  >> 4
	block_offset = address & 0xf
	block_begin_addr = address & 0xfff0
	tag = address >> 8
	return slot_num, block_offset, block_begin_addr, tag


def make_cache():
	cache = []
	for i in range(16):
		row_temp = cache_row(i)
		cache.append(row_temp)
	return cache

def display_cache():
	vhex = np.vectorize(hex)
	for i in range(len(cache)):
		print vhex(cache[i].slot),  cache[i].hit,  cache[i].tag, vhex(cache[i].data)

def cache_read(slot_num, block_offset, block_begin_addr, tag):
	packet = main_mem.get_block(block_begin_addr)
	cache_row = cache[slot_num]
	if cache_row.check_hit() == False:
		print 'miss'
		cache_row.change_hit()
		cache_row.update_tag(tag)
		cache_row.update_data(packet)
	else:
		print 'hit'
		if cache_row.check_tag(tag) == False:
			print 'tag miss'
			cache_row.update_tag(tag)
			cache_row.update_data(packet)
		else:
			print 'tag hit'
			pass

main_mem = memory()
cache = make_cache()

read_array = [0x7a2, 0x2e, 0x2f, 0x3d5, 0x4d5]
for hx in read_array:
	slot_num, block_offset, block_begin_addr, tag = parse_address(hx)
	cache_read(slot_num, block_offset, block_begin_addr, tag)

display_cache()










