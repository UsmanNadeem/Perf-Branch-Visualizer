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

# sys.path.append('/home/usman/Desktop/kernelPToct17/linux-4.14-rc4/tools/perf/scripts/python/Perf-Trace-Util/lib/Perf/Trace')

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
# inputFile = open(foldername+".txt" ,'r') 
		
branchaddrdict={}

takenCount = {}
nottakenCount = {}
TNTcount = {}
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
			takenCount[adr] = 0
			nottakenCount[adr] = 0
			TNTcount[adr] = []

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
executedCount = {}
for key in branchaddrdict.iterkeys():
	executedCount[key] = {}


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
	global executedCount
	global branchaddrdict
	global takenCount
	global nottakenCount
	global TNTcount
	global conditionalBranches
	global lastBranch

	timeCurrent = param_dict["sample"]['time']/1000000

	if timeStart == 0:
		timeStart = timeCurrent

	# if timeLast != 0 and timeLast != timeCurrent:	# initialize executedCount for all branches with 0
	# 	for x in xrange(1, timeCurrent - timeLast + 1):	# also add 0 for time period  not in trace
	# 		for key in branchaddrdict.iterkeys():
	# 			if timeLast+x not in executedCount[key]:
	# 				executedCount[key][timeLast+x] = 0

	# if timeLast == 0:	# first iteration 
	# 	for key in branchaddrdict.iterkeys():
	# 		executedCount[key][timeCurrent] = 0

	#if adr is 0:    # jump from kernel or some other unkown location etc.
		#continue


	# T/NT information
	if lastBranch != 0:		# last perf event was a branch
		if adr == branchaddrdict[lastBranch]:		# taken branch  curr adr = target of lastBranch
			takenCount[lastBranch] = takenCount[lastBranch] + 1
			TNTcount[lastBranch].append(True);
			# globalmap.write(str(timeLast) + "\t" + format(lastBranch, "x") + "\t1\n") 

		else:		# not taken branch
			nottakenCount[lastBranch] = nottakenCount[lastBranch] + 1
			TNTcount[lastBranch].append(False);
			# globalmap.write(str(timeLast) + "\t" + format(lastBranch, "x") + "\t0\n") 

	# Branch exec frequency
	if adr in branchaddrdict:		# branch executed ... could be T or NT
		lastBranch = adr
		if timeCurrent not in executedCount[lastBranch]:
			executedCount[lastBranch][timeCurrent] = 0
		executedCount[lastBranch][timeCurrent] = executedCount[lastBranch][timeCurrent] + 1
		
	else:		# non-branch instruction
		lastBranch = 0

	timeEnd = timeCurrent
	timeLast = timeCurrent



def trace_end():
	print "Done processing the perf trace"

	global timeCurrent
	global timeStart
	global timeLast
	global timeEnd
	global timeMultiplier
	global executedCount
	global branchaddrdict
	global takenCount
	global nottakenCount
	global TNTcount
	global conditionalBranches
	global lastBranch
	global foldername

	#print "T:"
	#for key, value in sorted(takenCount.iteritems()):
	#	print "\t", hex(key), ":", value

	#print "\n\nNT:"
	#for key, value in sorted(nottakenCount.iteritems()):
	#	print "\t", hex(key), ":", value
	
# todo print commented out
	# print "\n\nBranch\tFrequency\tTaken\tNotTaken"
	# for key, value in sorted(takenCount.iteritems()):
	# 	if takenCount[key]+nottakenCount[key] >= 300:  # cold branch
	# 		print format(int(key), 'x'), "\t", format(value+nottakenCount[key], "d"), "\t", value, "\t", nottakenCount[key]

	numHot = 0
	for key, value in sorted(takenCount.iteritems()):
		if takenCount[key]+nottakenCount[key] >= 300:  # cold branch
			numHot = numHot + 1

	print "*** Num Branches executed more than 300 times = ", numHot
	# globalmap.close()

	# if not os.path.exists(os.path.abspath(foldername)):
	#     try:
	#         os.makedirs(os.path.abspath(foldername))
	#     except OSError as exc:
	#         if exc.errno != errno.EEXIST:
	#             raise
	# print "Data in folder: ", os.path.abspath(foldername)

	print "Making Graphs"

	# temp = os.path.join(os.path.abspath(foldername), "globalheatmap-"+sys.argv[2]+".html")
	# print "Opening file: ", temp

	###############################################################################################################################
	# Plotting the global heatmap for hot branches
	###############################################################################################################################

	print "Processing the globalheatmap data"

	hot_branchList = []
	minTgraph = timeEnd+1
	maxTgraph = timeStart

	# calculate the min and max time for the x axis for only hot branches
	for adr in branchaddrdict.keys():
		if takenCount[adr]+nottakenCount[adr] < 300:  # cold branch
			continue
		hot_branchList.append(adr)
		freq = executedCount[adr]

		for t in xrange(timeStart, timeEnd+1):
			if t in freq:
				if t <= minTgraph:
					minTgraph = t
				if t >= maxTgraph:
					maxTgraph = t

	y = []
	z = []
	x = range(minTgraph, maxTgraph+1)
	nonEmptyTime = []

	for time_curr in x:
		for adr in hot_branchList:
			freq = executedCount[adr]
			if time_curr in freq and freq[time_curr] != 0:
				nonEmptyTime.append(time_curr)
				break

	hot_branchList.sort()
	x = nonEmptyTime

	for adr in hot_branchList:
		curr_z_row = []
		y.append("0x" + format(adr, "x"))
		freq = executedCount[adr]

		for time_curr in x:
			if time_curr in freq:
				curr_z_row.append(freq[time_curr])	# freq for this <branch, time>
			else:
				curr_z_row.append(0)	# this particular branch was not executed in this particular time unit

		z.append(list(curr_z_row))

	print "Done processing the globalheatmap data"

	print "Plotting the globalheatmap data"

	
	data = [
		go.Heatmap(
			z=z,
			x=x,
			y=y,
			# colorscale='Viridis',
			# colorscale=[[0, 'rgb(0,0,0)'], [1, 'rgb(255,0,0)']],
			colorscale=[[0, 'rgb(255,255,255)'], [0.01, 'rgb(255,218,218)'], [1, 'rgb(171,0,0)']],
			hoverinfo="x+y+z"
		)
	]

	layout = go.Layout(
		title='Branch frequency Heatmap'+"-"+foldername,
		xaxis = dict(ticks='', nticks=15, type="linear", title="Time(ticks)"),
		yaxis = dict(ticks='' , type="category", title="Branches")
	)

	fig1 = go.Figure(data=data, layout=layout)

	graphFile = open("globalheatmap-"+foldername+".html" ,'w') 
	graphFile.write(plotly.offline.plot(fig1, filename="heatmap-hotbranches-"+foldername+".html",  auto_open=False, output_type='div')) 

	print "Done plotting the globalheatmap data"


	###############################################################################################################################
	# Plotting the Branch Total frequency w/ T/NT count
	###############################################################################################################################

	print "Plotting the Branch Total frequency"
	t1 = []
	t2 = []
	t3 = []
	
	branchListLabels = []

	for key in sorted(takenCount.iterkeys()):
		branchListLabels.append("0x" + format(key, "x"))
		t1.append(takenCount[key] + nottakenCount[key])
		t2.append(takenCount[key])
		t3.append(nottakenCount[key])

	trace1 = go.Bar(
		x=branchListLabels,
		y=t1,
		name='Total'
	)
	trace2 = go.Bar(
		x=branchListLabels,
		y=t2,
		name='Taken'
	)
	trace3 = go.Bar(
		x=branchListLabels,
		y=t3,
		name='NotTaken'
	)

	data = [trace1, trace3, trace2]
	layout = go.Layout(
		title='All branches execution/taken/nottakenCount-'+foldername,
		barmode='group',
		# yaxis = dict(ticks='', type="log", title="Count"),
		yaxis = dict(ticks='', type="linear", title="Count"),
		xaxis = dict(ticks='' , type="category", title="Branches")
	)

	fig2 = go.Figure(data=data, layout=layout)

	graphFile.write(plotly.offline.plot(fig2, filename="globalheatmap-"+foldername+".html",  auto_open=False, output_type='div')) 

	print "Done plotting the Branch Total frequency"


	###############################################################################################################################
	# Sorting hot branches by bias to make a seperate bar chart
	###############################################################################################################################
	print "Plotting the branches by bias"

	bias_keyed_hotbranches = {}
	for adr in hot_branchList:
		bias = 1
		if takenCount[adr] == 0 or nottakenCount[adr] == 0:
			pass
		else:
			bias = float(min(takenCount[adr], nottakenCount[adr])) / float(max(takenCount[adr], nottakenCount[adr]))
			bias = 1.0 - float(bias)
		bias_keyed_hotbranches[adr] = bias

	t1 = []
	t2 = []
	t3 = []

	hotbranchListLabels = []

	# for key in sorted(bias_keyed_hotbranches.iterkeys()):
	for key, value in sorted(bias_keyed_hotbranches.iteritems(), key=lambda x:x[1], reverse=True):
		# key=bias_keyed_hotbranches.get, reverse=True):
		# print key, value
		hotbranchListLabels.append("0x" + format(key, "x"))
		t1.append(takenCount[key] + nottakenCount[key])
		t2.append(takenCount[key])
		t3.append(nottakenCount[key])


	trace1 = go.Bar(
		x=hotbranchListLabels,
		y=t1,
		name='Total'
	)
	trace2 = go.Bar(
		x=hotbranchListLabels,
		y=t2,
		name='Taken'
	)
	trace3 = go.Bar(
		x=hotbranchListLabels,
		y=t3,
		name='NotTaken'
	)

	data = [trace1, trace3, trace2]
	layout = go.Layout(
		title='Hot branches execution/taken/nottakenCount-'+foldername+" Sort by bias",
		barmode='group',
		# yaxis = dict(ticks='', type="log", title="Count"),
		yaxis = dict(ticks='', type="linear", title="Count"),
		xaxis = dict(ticks='' , type="category", title="Branches")
	)

	fig2 = go.Figure(data=data, layout=layout)

	graphFile.write(plotly.offline.plot(fig2, filename="globalheatmap-"+foldername+".html",  auto_open=False, output_type='div')) 
	graphFile.close()

	print "Done plotting the branches by bias"



	###############################################################################################################################
	# Individual files for Branch T/NT Phase data
	###############################################################################################################################

	print "Plotting the Branch T/NT Phase data"
	for i, key in enumerate(sorted(TNTcount.iterkeys())):
		if takenCount[key]+nottakenCount[key] < 300:	# no need to plot cold branches
			continue
		graphFile = open("branchphase"+branchListLabels[i]+"-"+foldername+".html",'w') 

		# y = []
		# for index in range(len(TNTcount[key])):
		# 	if index == 0:
		# 		y.append(TNTcount[key][index])
		# 		continue
		# 	if TNTcount[key][index] == TNTcount[key][index-1]:
		# 		y.append(None)
		# 		continue
		# 	y.append(TNTcount[key][index])

		# trace1 = go.Scatter(x = range(len(TNTcount[key])), y=y, line=dict(shape='hv'), mode='lines+markers', connectgaps=True)
		trace1 = go.Scatter(x = range(len(TNTcount[key])), y=TNTcount[key], line=dict(shape='hv'), mode='lines', connectgaps=True)
		# trace1 = go.Scatter(x = range(len(TNTcount[key])), y=TNTcount[key], line=dict(shape='hv'), mode='markers')
		data = [trace1]
		percentage = takenCount[key]*100/(takenCount[key]+nottakenCount[key])
		layout = go.Layout(
			title='T/NT Phase '+branchListLabels[i]+"- Taken="+ format(percentage, "d") + "% NotTaken="+ format(100-percentage, "d")   +"% - "+foldername,
			# yaxis = dict(ticks='', type="category", rangemode="tozero", fixedrange=True, range=[0, 3], title="T=True NT=False"),
			yaxis = dict(ticks='', type="category", title="T=True NT=False"),
			xaxis = dict(ticks='', nticks=6, title="Executions")
		)
		fig3 = go.Figure(data=data, layout=layout)
		graphFile.write(plotly.offline.plot(fig3, filename="branchphase"+branchListLabels[i]+"-"+foldername+".html",  auto_open=False, output_type='div')) 

		###############################################################################################################################
		# Now drawing taken bias and not taken bias
		###############################################################################################################################

		takenBias = 0
		notTakenBias = 0
		takenBiasList = []
		notTakenBiasList = []

		for x in TNTcount[key]:
			if x is True:
				takenBias = takenBias + 1
				notTakenBias = 0
				takenBiasList.append(takenBias)
				notTakenBiasList.append(notTakenBias)
			if x is False:
				takenBias = 0
				notTakenBias = notTakenBias + 1
				takenBiasList.append(takenBias)
				notTakenBiasList.append(notTakenBias)


		trace1 = go.Scatter(x = range(len(TNTcount[key])), y=takenBiasList, line=dict(shape='spline', color = ('red')), mode='lines', name='takenCount')
		trace2 = go.Scatter(x = range(len(TNTcount[key])), y=notTakenBiasList, line=dict(shape='spline', color = ('blue')), mode='lines', name='notTakenCount')

		data = [trace1, trace2]
		layout = go.Layout(
			title='T/NT Phase over time'+branchListLabels[i]+" - "+foldername,
			yaxis = dict(ticks='', type="linear", title="T/NT Count"),
			xaxis = dict(ticks='', nticks=6, title="Executions")
		)
		fig3 = go.Figure(data=data, layout=layout)
		graphFile.write(plotly.offline.plot(fig3, filename="branchphase"+branchListLabels[i]+"-"+foldername+".html",  auto_open=False, output_type='div')) 


		graphFile.close()

	print "Done plotting the Branch T/NT Phase data"
