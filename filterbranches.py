#!/usr/bin/python
# original from Furat F Afram: add assembler code to trace, hacked by AK
import re
import sys
import os
from decimal import Decimal
import plotly
import plotly.graph_objs as go
import errno
import operator


sys.path.append(os.environ['PERF_EXEC_PATH'] + \
		'/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

from perf_trace_context import *
from EventClass import *

def trace_begin():
	print sys.argv




if (len(sys.argv)!=3):
		# print ("Usage: perf script --itrace=i100ns -Ftime,ip | ./map.py ./a.out a.out100ns")
		print ("Usage: perf script --itrace=i1us -i perf.data -s ./map.py ./a.out a.out100ns")
		# print ("Or to profile")
		# print ("Usage: perf script --itrace=i10ns -Ftime,ip | python -m cProfile -s cumtime ./map.py ./a.out identifier")
		sys.exit(0)

foldername = sys.argv[2]
outputFile = open(foldername+".txt" ,'w') 

branchaddrdict={}

# unconditionalBranches = ["jmpq", "callq", "retq"]
conditionalBranches = ["jns", "js", "jnz", "jz", "jno", "jo", "jbe", "jb", "jle", "jl", "jae", "ja", "jge", "jg", "jne", "je", "jnae", "jc", "jnc", "jnb", "jna", "jnbe", "jnge", "jnl", "jng", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz"]
mina = 0xffffffffffffffff
maxa = 0
asmfile = os.popen("objdump -d " + sys.argv[1]);

print "Processing the objdump for conditionalBranches"

for i in asmfile:
	if not re.match(r'\s*[0-9a-f]+:', i):
		continue

	s = i.split()
	if (len(s)<3 or len(i)<30):    # no instruction e.g.   "40070e:	00 00  ...endline"
		pass
	else:		
		adr = int(s[0].strip(":"), 16)
		instr = i[30:-1]
		opcode = instr.split()[0]
		
		if opcode in conditionalBranches:    # only create map for conditionalBranches
			firstarg = instr.split()[1]
			branchaddrdict[adr] = int(firstarg, 16) 

			mina = min(mina, adr)
			maxa = max(maxa, adr)
			#print hex(adr),":", instr 

asmfile.close()
	

print "Done processing the objdump for conditionalBranches"
print "Total number of conditionalBranches: ", len(branchaddrdict)

lastBranch = 0

timeCurrent = 0
timeStart = 0
timeLast = 0
timeEnd = 0
timeMultiplier = 1000000


print "Processing the perf trace"




# globalmap = open("globalmap"+"-"+sys.argv[2]+".txt",'w') 
def process_event(param_dict):
	# sample     = param_dict["sample"]
	# name       = param_dict["ev_name"]
	adr = param_dict["sample"]['ip']
	# timeCurrent = int(Decimal(trace[0].strip(":"))*timeMultiplier)
	global timeCurrent
	global timeStart
	global timeLast
	global timeEnd
	global timeMultiplier
	global branchaddrdict
	global lastBranch

	timeCurrent = param_dict["sample"]['time']/1000000

	if timeStart == 0:
		timeStart = timeCurrent


	# T/NT information
	if lastBranch != 0:		# last perf event was a branch
		if adr == branchaddrdict[lastBranch]:		# taken branch  curr adr = target of lastBranch
			outputFile.write(str(timeLast) + " " + str(lastBranch) + " T\n")

		else:		# not taken branch
			outputFile.write(str(timeLast) + " " + str(lastBranch) + " NT\n")

	# Branch exec frequency
	if adr in branchaddrdict:		# branch executed ... could be T or NT
		lastBranch = adr
		
	else:		# non-branch instruction
		lastBranch = 0

	timeEnd = timeCurrent
	timeLast = timeCurrent



def trace_end():
	print "Done processing the perf trace"
	outputFile.close()
