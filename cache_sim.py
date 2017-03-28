import numpy as np

global cache
global main_mem


class memory:
	def __init__(self):
		self.main_mem = self.make_mem()

	# intialize memory
	def make_mem(self):
		array = range(0, 0xff + 0x1)
		lol_main_memory = []
		for i in range(8):
			lol_main_memory.append(array)
		main_memory = sum(lol_main_memory, [])
		return main_memory

	def get_block(self, block_begin_addr):
		return self.main_mem[block_begin_addr: block_begin_addr + 0xf + 1]

	def set_block(self, block_begin_addr, packet):
		self.main_mem[block_begin_addr: block_begin_addr + 0xf + 1] = packet

	def print_main_mem(self):
		print self.main_mem


class cache_row:

	'''
	slot - slot number of cache
	hit - cache hit = 1, cache miss = 0.  Initalized at miss
	tag - tag number on cache
	data - initialize at an array of 16 0's
	current_block_begin - remember initial block begin address to reference memory on putback after cache miss
	'''
	def __init__(self, slot):
		self.slot = slot
		self.hit = 0
		self.tag = 0
		self.data = [0] * 16
		self.current_block_begin = 0

	# check if there's a hit
	def check_hit(self):
		if self.hit == 1:
			return True
		if self.hit == 0:
			return False

	# change hit value when read is made
	def change_hit(self):
		self.hit = 1

	# check tag value match
	def check_tag(self, tag):
		if self.tag == tag:
			return True
		else:
			return False

	# update tag with new on read
	def update_tag(self, tag):
		self.tag = tag

	# bring in data from main memory given as data
	def update_data(self, data):
		self.data = data

	# write to slot with offset of -1 // this might change
	def write_data(self, offset, write_data):
		self.data[offset] = write_data  # check if offset happens left or right

	# create a reference to where address is in memory.  This only saves a few lines of code so I didn't have to go back and in parse packet
	def update_begin_addr(self, begin_address):
		self.current_block_begin = begin_address

	# show value at offset
	def show_value(self, offset):
		print "Data Value ", hex(self.data[offset])


# parse address into keys used for read, write, display
def parse_address(address):
	slot_num = (address & 0x00f0) >> 4
	block_offset = address & 0xf
	block_begin_addr = address & 0xfff0
	tag = address >> 8
	return slot_num, block_offset, block_begin_addr, tag


# make the cache with 16 cache rows.
def initialize_cache():
	cache = []
	for i in range(16):
		row_temp = cache_row(i)
		cache.append(row_temp)
	return cache


# display cache as hex with vhex
def display_cache():
	vhex = np.vectorize(hex)
	print "Slot   Valid   Tag                     Data"
	for i in range(len(cache)):
		print vhex(cache[i].slot), cache[i].hit, vhex(cache[i].tag), vhex(cache[i].data)


# main function on run
def cache_do(address, *write_data):
	# parse address
	slot_num, block_offset, block_begin_addr, tag = parse_address(address)
	# get input data if it were.  Parse from tuple. Expect only one
	for data in write_data:
		input_data = data
	# get packet from MM
	packet = main_mem.get_block(block_begin_addr)
	# get cache row object from slot number
	cache_row = cache[slot_num]
	# if not hit
	if cache_row.check_hit() is False:
		print 'At given address, there is a CACHE MISS -- pulling in data from MM'
		cache_row.change_hit()
		cache_row.update_tag(tag)
		cache_row.update_data(packet)
		cache_row.show_value(block_offset)
		cache_row.update_begin_addr(block_begin_addr)
		if write_data:
			print 'Has changed to: '
			cache_row.write_data(block_offset, input_data)
			cache_row.show_value(block_offset)
	else:
		# if hit, but tag doesn't match
		if cache_row.check_tag(tag) is False:
			print 'At given address, there is a CACHE MISS-- pulling in data from MM'
			main_mem.set_block(cache_row.current_block_begin, cache_row.data)
			cache_row.update_tag(tag)
			cache_row.update_data(packet)
			cache_row.show_value(block_offset)
			cache_row.update_begin_addr(block_begin_addr)
			# if data was given, write it to correct slot
			if write_data:
				print 'Has changed to: '
				cache_row.write_data(block_offset, input_data)
				cache_row.show_value(block_offset)
		# if cache hit, don't access main memory -- create dirty block.
		else:
			print 'At given address, there is a CACHE HIT'
			cache_row.show_value(block_offset)
			# if data was given, write it to correct slot
			if write_data:
				print 'Has changed to: '
				cache_row.write_data(block_offset, input_data)
				cache_row.show_value(block_offset)
			pass
	print


# assign value to globals
cache = initialize_cache()
main_mem = memory()


# run main recursively and handle user errors.
def main():
	rwd = raw_input("(R)ead, (W)rite, (D)isplay, (Q)uit:  ")
	form_rwd = rwd.lower()
	if form_rwd == 'q':
		return
	elif form_rwd != 'q':
		if form_rwd == 'd':
			display_cache()
		elif form_rwd == 'r':
			read = raw_input("Enter Hex Address:  ")
			read_int = int(read, 16)
			cache_do(read_int)
		elif form_rwd == 'w':
			write = raw_input("Enter Hex Address:  ")
			write_int = int(write, 16)
			value = raw_input("Enter New Data to replace Hex:  ")
			value_int = int(value, 16)
			cache_do(write_int, value_int)
		else:
			print "Entered the wrong value, try again - to Quit press q"
		main()
	else:
		main()

# initialize main() on run
main()
