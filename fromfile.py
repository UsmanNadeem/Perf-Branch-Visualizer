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
import gc
import cPickle

from itertools import izip

def grouped(iterable, n):
	"s -> (s0,s1,s2,...sn-1), (sn,sn+1,sn+2,...s2n-1), (s2n,s2n+1,s2n+2,...s3n-1), ..."
	return izip(*[iter(iterable)]*n)


print sys.argv
if (len(sys.argv)!=3):
		# print ("Usage: perf script --itrace=i100ns -Ftime,ip | ./map.py ./a.out a.out100ns")
		print ("Usage: ./fromfile.py ./a.out a.out100ns")
		# print ("Or to profile")
		# print ("Usage: perf script --itrace=i10ns -Ftime,ip | python -m cProfile -s cumtime ./map.py ./a.out identifier")
		sys.exit(0)

foldername = sys.argv[2]
		
branchaddrdict={}

takenCount = {}
nottakenCount = {}
TNTcount = {}
# unconditionalBranches = ["jmpq", "callq", "retq"]
conditionalBranches = ["jns", "js", "jnz", "jz", "jno", "jo", "jbe", "jb", "jle", "jl", "jae", "ja", "jge", "jg", "jne", "je", "jnae", "jc", "jnc", "jnb", "jna", "jnbe", "jnge", "jnl", "jng", "jnle", "jp", "jpe", "jnp", "jpo", "jcxz", "jecxz"]
mina = 0xffffffffffffffff
maxa = 0
asmfile = os.popen("objdump -d " + sys.argv[1]);

tempbranchPhaseMonitor = {}
print "Processing the objdump for conditionalBranches"

for i in asmfile:
	if not re.match(r'\s*[0-9a-f]+:', i):
		continue

	s = i.split()
	if (len(s)<3 or len(i)<30):    # no instruction e.g.   "40070e:	00 00  ...endline"
		pass
	else:		
		adr = str(int(s[0].strip(":"), 16))
		instr = i[30:-1]
		opcode = instr.split()[0]
		
		if opcode in conditionalBranches:    # only create map for conditionalBranches
			firstarg = instr.split()[1]
			branchaddrdict[adr] = str(int(firstarg, 16)) 
			takenCount[adr] = 0
			nottakenCount[adr] = 0
			TNTcount[adr] = []

			tempbranchPhaseMonitor[adr] = {}
			tempbranchPhaseMonitor[adr]["T"] = 0
			tempbranchPhaseMonitor[adr]["NT"] = 0

			mina = min(mina, adr)
			maxa = max(maxa, adr)
			#print hex(adr),":", instr 

asmfile.close()
gc.collect()
print "Done processing the objdump for conditionalBranches"
print "Total number of conditionalBranches: ", len(branchaddrdict)


###############################################################################################################################
# processing trace file
###############################################################################################################################


executedCount = {}

for key in branchaddrdict.iterkeys():
	executedCount[key] = {}


print "Processing the trace file"

inputFile = open(foldername+".txt" ,'r') 



### commented out because its slower ###

# timeStart = inputFile.read(10)
# inputFile.seek(0, 0)

# try:
#     line = inputFile.read(21)  #also read new line char in case of "T"

#     while line != "":
# 		timeCurrent = line[0:0+10]
# 		adr = line[11:11+7]
		
# 		if line[19:19+1] == "T":
# 			takenCount[adr] = takenCount[adr] + 1
# 			TNTcount[adr].append(True);
# 		else:
# 			nottakenCount[adr] = nottakenCount[adr] + 1
# 			TNTcount[adr].append(False);
# 			inputFile.seek(1, 1)


# 		if timeCurrent not in executedCount[adr]:
# 			executedCount[adr][timeCurrent] = 0

# 		executedCount[adr][timeCurrent] = executedCount[adr][timeCurrent] + 1
# 		line = inputFile.read(21)
# finally:
# 	timeEnd = timeCurrent
# 	inputFile.close()

timeCurrent = 0
timeCurrentStr = ""
timeStart = 0
totalExecCount = 0

for line in inputFile:
	timeCurrentStr = line[0:0+10]
	timeStart = int(timeCurrentStr)
	break

i = 0
branchesWithPhases = {}
flag1 = False
flag2 = False

for line in inputFile:
	if timeCurrentStr == line[0:0+10]:
		pass
	else:
		timeCurrentStr = line[0:0+10]
		timeCurrent = int(timeCurrentStr)

	adr = line[11:11+7]

	
	if timeCurrent not in executedCount[adr]:
		executedCount[adr][timeCurrent] = 0


	if adr not in branchesWithPhases:
		if flag1 == False or flag2 == False:
			if tempbranchPhaseMonitor[adr]["NT"] > 10000:
				flag1 = True
			if tempbranchPhaseMonitor[adr]["T"] > 10000:
				flag2 = True
		if flag1 == True and flag2 == True:
			branchesWithPhases[adr] = 10000
			TNTcount[adr].append(0)
			TNTcount[adr].append(0)
			TNTcount[adr].append(0)
	else:
		branchesWithPhases[adr] = branchesWithPhases[adr] + 1

	if line[19:19+1] == "T":
		takenCount[adr] = takenCount[adr] + 1
		if adr in branchesWithPhases:
			if tempbranchPhaseMonitor[adr]["NT"] > 10000:
				TNTcount[adr].append(branchesWithPhases[adr]-tempbranchPhaseMonitor[adr]["NT"])
				TNTcount[adr].append(0)
				TNTcount[adr].append(0)
				TNTcount[adr].append(branchesWithPhases[adr])
				TNTcount[adr].append(tempbranchPhaseMonitor[adr]["T"])
				TNTcount[adr].append(tempbranchPhaseMonitor[adr]["NT"])
			elif not (TNTcount[adr][-1] == 0 and TNTcount[adr][-2] == 0):
				TNTcount[adr].append(branchesWithPhases[adr])
				TNTcount[adr].append(0)
				TNTcount[adr].append(0)

		tempbranchPhaseMonitor[adr]["T"] = tempbranchPhaseMonitor[adr]["T"] + 1
		tempbranchPhaseMonitor[adr]["NT"] = 0
	else:
		nottakenCount[adr] = nottakenCount[adr] + 1
		if adr in branchesWithPhases:
			if tempbranchPhaseMonitor[adr]["T"] > 10000:
				TNTcount[adr].append(branchesWithPhases[adr]-tempbranchPhaseMonitor[adr]["T"])
				TNTcount[adr].append(0)
				TNTcount[adr].append(0)
				TNTcount[adr].append(branchesWithPhases[adr])
				TNTcount[adr].append(tempbranchPhaseMonitor[adr]["T"])
				TNTcount[adr].append(tempbranchPhaseMonitor[adr]["NT"])
			elif not (TNTcount[adr][-1] == 0 and TNTcount[adr][-2] == 0):
				TNTcount[adr].append(branchesWithPhases[adr])
				TNTcount[adr].append(0)
				TNTcount[adr].append(0)

		tempbranchPhaseMonitor[adr]["NT"] = tempbranchPhaseMonitor[adr]["NT"] + 1
		tempbranchPhaseMonitor[adr]["T"] = 0

	# if adr not in branchesWithPhases:
	# 	if tempbranchPhaseMonitor[adr]["NT"] > 10000 or tempbranchPhaseMonitor[adr]["T"] > 10000:
	# 		branchesWithPhases[adr] = 0
	# 		TNTcount[adr].append(0)
	# 		TNTcount[adr].append(0)
	# 		TNTcount[adr].append(0)
	# else:
	# 	branchesWithPhases[adr] = branchesWithPhases[adr] + 1
	# 	if tempbranchPhaseMonitor[adr]["NT"] == 0 and TNTcount[adr][-2] != 0:
	# 		pass
	# 	if tempbranchPhaseMonitor[adr]["NT"] == 0 or tempbranchPhaseMonitor[adr]["T"] == 0:
	# 		if tempbranchPhaseMonitor[adr]["NT"] > 10000 or tempbranchPhaseMonitor[adr]["T"] > 10000:
	# 			TNTcount[adr].append(branchesWithPhases[adr])
	# 			TNTcount[adr].append(tempbranchPhaseMonitor[adr]["T"])
	# 			TNTcount[adr].append(tempbranchPhaseMonitor[adr]["NT"])
	# 		elif TNTcount[adr][-1] != 0 and TNTcount[adr][-2] != 0:
	# 			TNTcount[adr].append(branchesWithPhases[adr])
	# 			TNTcount[adr].append(0)
	# 			TNTcount[adr].append(0)




	totalExecCount = totalExecCount + 1
	executedCount[adr][timeCurrent] = executedCount[adr][timeCurrent] + 1
	# i = i + 1
	# if i == 50000000:
		# print sys.getsizeof(cPickle.dumps(executedCount)), sys.getsizeof(cPickle.dumps(TNTcount)), sys.getsizeof(cPickle.dumps(takenCount))
		# break
		# sys.exit()

inputFile.close()
timeEnd = timeCurrent
gc.collect()

print "Done processing the trace file"




###############################################################################################################################
#  write processed info to a file for comaparison with other inputs
###############################################################################################################################
print "Further processing the data"

numHot = 0
hot_branchList = []

# for correspondence:
# print <branch> <mostly taken (1) or not taken (0)> <total exec count>
# for overlap:
# print <branch> <total T count> <total NT count>

correspondenceFile = open(foldername+"-correspondence.txt" ,'w') 
overlapFile = open(foldername+"-overlap.txt" ,'w') 
for adr, Tcount in takenCount.iteritems():
	NTcount = nottakenCount[adr]
	mostlyTNT = 0
	totalCount = Tcount+NTcount
	# todo what if equal
	if Tcount > NTcount:
		mostlyTNT = 1

	# write to the two output files
	correspondenceFile.write(adr + " " + str(mostlyTNT) + " " + str(totalCount) + "\n")
	overlapFile.write(adr  + " " + str(Tcount) + " " + str(NTcount) + "\n")

	# for calculating hot branches:
	# if executed count > 1% of total then hot
	if totalExecCount > 0 and totalCount/float(totalExecCount) > 0.005:
		numHot = numHot + 1
		hot_branchList.append(adr)

correspondenceFile.close()
overlapFile.close()

print "Dont Further processing the data"

print "*** Num hot branches =", numHot#, hot_branchList
print "*** Num branches with Phase > 1000 =", len(branchesWithPhases)#, branchesWithPhases



###############################################################################################################################
# Plotting the global heatmap for hot branches
###############################################################################################################################
print "Making Graphs"

print "Processing the globalheatmap data"

y = []
z = []
x = range(timeStart, timeEnd+1)

hot_branchList.sort()

for adr in hot_branchList:
	curr_z_row = []
	y.append("0x" + format(int(adr), 'x'))
	freq = executedCount[adr]

	for time_curr in x:
		if time_curr in freq:
			curr_z_row.append(freq[time_curr])	# freq for this branch and time
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

# sys.exit()
###############################################################################################################################
# Plotting the Branch Total frequency w/ T/NT count
###############################################################################################################################

print "Plotting the Branch Total frequency"
t1 = []
t2 = []
t3 = []

branchListLabels = []

for key in sorted(takenCount.iterkeys()):
	branchListLabels.append("0x" + format(int(key), 'x'))
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

bias_keyed_hotbranches = {} 	# <adr, bias>
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
	hotbranchListLabels.append("0x" + format(int(key), 'x'))
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
	# no need to plot cold branches
	if key not in hot_branchList:
		continue
	if key not in branchesWithPhases:
		continue
	if bias_keyed_hotbranches[key] > 0.9:
		continue


	graphFile = open("branchphase"+branchListLabels[i]+"-"+foldername+".html",'w') 

	# # y = []
	# # for index in range(len(TNTcount[key])):
	# # 	if index == 0:
	# # 		y.append(TNTcount[key][index])
	# # 		continue
	# # 	if TNTcount[key][index] == TNTcount[key][index-1]:
	# # 		y.append(None)
	# # 		continue
	# # 	y.append(TNTcount[key][index])

	# # trace1 = go.Scatter(x = range(len(TNTcount[key])), y=y, line=dict(shape='hv'), mode='lines+markers', connectgaps=True)

	# # print "len", len(TNTcount[key]),  TNTcount[key]
	# trace1 = go.Scatter(x = range(len(TNTcount[key])), y=TNTcount[key], line=dict(shape='hv'), mode='lines', connectgaps=True)
	# # trace1 = go.Scatter(x = range(len(TNTcount[key])), y=TNTcount[key], line=dict(shape='hv'), mode='markers')
	# data = [trace1]
	percentage = takenCount[key]*100/(takenCount[key]+nottakenCount[key])
	# layout = go.Layout(
	# 	title='T/NT Phase '+branchListLabels[i]+"- Taken="+ format(percentage, "d") + "% NotTaken="+ format(100-percentage, "d")   +"% - "+foldername,
	# 	# yaxis = dict(ticks='', type="category", rangemode="tozero", fixedrange=True, range=[0, 3], title="T=True NT=False"),
	# 	yaxis = dict(ticks='', type="category", title="T=True NT=False"),
	# 	xaxis = dict(ticks='', nticks=6, title="Executions")
	# )
	# fig3 = go.Figure(data=data, layout=layout)
	# graphFile.write(plotly.offline.plot(fig3, filename="branchphase"+branchListLabels[i]+"-"+foldername+".html",  auto_open=False, output_type='div')) 
	# # graphFile.write(plotly.offline.plot(fig3, image_filename="branchphase"+branchListLabels[i]+"-"+foldername+".svg",  auto_open=False, image = 'svg')) 

	###############################################################################################################################
	# Now drawing taken bias and not taken bias
	###############################################################################################################################

	# TNTcount[adr].append(branchesWithPhases[adr])
	# TNTcount[adr].append("T" + str(tempbranchPhaseMonitor[adr]["T"]))
	# TNTcount[adr].append("N" + str(tempbranchPhaseMonitor[adr]["NT"]))

	x = []
	takenBiasList = []
	notTakenBiasList = []
	for a, b, c in grouped(TNTcount[key], 3):
		x.append(a)
		takenBiasList.append(b)
		notTakenBiasList.append(c)

	print branchListLabels[i]+'/'+str(key), len(x), len(takenBiasList), len(notTakenBiasList)
	trace1 = go.Scatter(x = x, y=takenBiasList, line=dict(shape='linear', color = ('red')), mode='lines', name='takenCount')
	trace2 = go.Scatter(x = x, y=notTakenBiasList, line=dict(shape='linear', color = ('blue')), mode='lines', name='notTakenCount')

	data = [trace1, trace2]
	layout = go.Layout(
		title='T/NT Phase over time'+branchListLabels[i]+"- Taken="+ format(percentage, "d") + "% NotTaken="+ format(100-percentage, "d")   +"% - "+foldername,
		yaxis = dict(ticks='', type="linear", title="T/NT Count"),
		xaxis = dict(ticks='', nticks=6, title="Executions")
	)
	fig3 = go.Figure(data=data, layout=layout)
	graphFile.write(plotly.offline.plot(fig3, filename="branchphase"+branchListLabels[i]+"-"+foldername+".html",  auto_open=False, output_type='div')) 


	graphFile.close()

print "Done plotting the Branch T/NT Phase data"


