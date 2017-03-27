import numpy as np
#initialize main memory here
global cache
global main_mem 

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

	def set_block(self, block_begin_addr, packet):
		self.main_mem[block_begin_addr : block_begin_addr + 0xf + 1] = packet

	def print_main_mem(self):
		print self.main_mem


class cache_row:
	def __init__(self, slot):
		self.slot = slot
		self.hit = 0
		self.tag = 0
		self.data = [0] * 16
		self.current_block_begin = 0

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

	def write_data(self, offset, write_data):
		self.data[-offset] = write_data	## check if offset happens left or right

	def update_begin_addr(self, begin_address):
		self.current_block_begin = begin_address


def parse_address(address):
	slot_num = (address & 0x00f0)  >> 4
	block_offset = address & 0xf
	block_begin_addr = address & 0xfff0
	tag = address >> 8
	return slot_num, block_offset, block_begin_addr, tag

def initialize_cache():
	cache = []
	for i in range(16):
		row_temp = cache_row(i)
		cache.append(row_temp)
	return cache

def display_cache():
	vhex = np.vectorize(hex)
	for i in range(len(cache)):
		print vhex(cache[i].slot),  cache[i].hit,  vhex(cache[i].tag), vhex(cache[i].data)

def cache_do(address, *write_data):
	slot_num, block_offset, block_begin_addr, tag = parse_address(address)
	for data in write_data:
		input_data = data
	packet = main_mem.get_block(block_begin_addr)
	cache_row = cache[slot_num]
	if cache_row.check_hit() == False:
		cache_row.change_hit()
		cache_row.update_tag(tag)
		cache_row.update_data(packet)
		cache_row.update_begin_addr(block_begin_addr)
		if write_data:
			cache_row.write_data(block_offset, input_data)
	else:
		if cache_row.check_tag(tag) == False:
			main_mem.set_block(cache_row.current_block_begin, cache_row.data)
			
			cache_row.update_tag(tag)
			cache_row.update_data(packet)
			cache_row.update_begin_addr(block_begin_addr)
			if write_data:
				cache_row.write_data(block_offset, input_data)
		else:
			if write_data:
				cache_row.write_data(block_offset, input_data)
			pass

cache = initialize_cache()
main_mem = memory()

def main():
	rwd = raw_input("(R)ead, (W)rite, (D)isplay, (Q)uit:  ")
	form_rwd = rwd.lower()
	if form_rwd != 'q':
		if form_rwd == 'd':
			display_cache()
		elif form_rwd == 'r':
			read = raw_input("Enter Hex Address:  ")
			read_int = int(read, 16)
			cache_do(read_int)
		elif form_rwd == 'w':
			write = raw_input("Enter Hex Address:  ") 
			write_int = int(write, 16)
			value = raw_input("Enter New Data in Hex:  ")
			value_int = int(value, 16)
			cache_do(write_int, value_int)
		main()
	elif form_rwd == 'q':
		return
	else:
		print "Entered the wrong value, try again - to Quit press q and enter"
		main()

main()












