#!/usr/bin/python
# original from Furat F Afram: add assembler code to trace, hacked by AK
import re
import sys
import os
from decimal import Decimal
import plotly
import plotly.graph_objs as go

if (len(sys.argv)!=3):
        print ("Usage: perf script --itrace=i1ns | ./map.py ./a.out identifier")
        sys.exit(0)

branchaddrdict={}

takenCount = {}
nottakenCount = {}
frequency = {}
TNTcount = {}
#unconditionalBranches = ["jmpq", "callq", "retq"]
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
			branchaddrdict[adr] = instr
			takenCount[adr] = 0
			nottakenCount[adr] = 0
			frequency[adr] = 0
			TNTcount[adr] = []

			mina = min(mina, adr)
			maxa = max(maxa, adr)
			#print hex(adr),":", instr 
	

print "Done processing the objdump for conditionalBranches"
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

globalmap = open("globalmap"+"-"+sys.argv[2]+".txt",'w') 
for line in sys.stdin:
	trace = line.split()
	if len(trace) < 7:
		continue

	adr = int(trace[6], 16)
	timeCurrent = int(Decimal(trace[3].strip(":"))*timeMultiplier)

	if timeStart == 0:
		timeStart = timeCurrent

	if timeLast != 0 and timeLast != timeCurrent:	# initialize executedCount for all branches with 0
		for x in xrange(1, timeCurrent - timeLast + 1):	# also add 0 for time period  not in trace
			for key in branchaddrdict.iterkeys():
				if timeLast+x not in executedCount[key]:
					executedCount[key][timeLast+x] = 0

	if timeLast == 0:	# first iteration 
		for key in branchaddrdict.iterkeys():
			executedCount[key][timeCurrent] = 0

	#if adr is 0:    # jump from kernel or some other unkown location etc.
		#continue


	# T/NT information
	if lastBranch != 0:		# last perf event was a branch
		if adr == int(branchaddrdict[lastBranch].split()[1], 16):		# taken branch  curr adr = target of lastBranch
			takenCount[lastBranch] = takenCount[lastBranch] + 1
			TNTcount[lastBranch].append(2);
			globalmap.write(str(timeLast) + "\t" + format(lastBranch, "x") + "\t1\n") 

		else:		# not taken branch
			nottakenCount[lastBranch] = nottakenCount[lastBranch] + 1
			TNTcount[lastBranch].append(1);
			globalmap.write(str(timeLast) + "\t" + format(lastBranch, "x") + "\t0\n") 

	# Branch exec frequency
	if adr in branchaddrdict:		# branch executed ... could be T or NT
		lastBranch = adr
		frequency[lastBranch] = frequency[lastBranch] + 1
		executedCount[lastBranch][timeCurrent] = executedCount[lastBranch][timeCurrent] + 1
		
	else:		# non-branch instruction
		lastBranch = 0

	timeEnd = timeCurrent
	timeLast = timeCurrent

print "Done processing the perf trace"

#print "T:"
#for key, value in sorted(takenCount.iteritems()):
#	print "\t", hex(key), ":", value

#print "\n\nNT:"
#for key, value in sorted(nottakenCount.iteritems()):
#	print "\t", hex(key), ":", value

print "\n\nBranch\tFrequency\tTaken\tNotTaken"
for key, value in sorted(frequency.iteritems()):
	print format(int(key), 'x'), "\t", value, "\t", takenCount[key], "\t", nottakenCount[key]
globalmap.close()


print "Making Graphs"
graphFile = open("globalheatmap"+"-"+sys.argv[2]+".html",'w') 

print "Processing the globalheatmap data"

x = []
branchList = branchaddrdict.keys()
branchList.sort()
z = []
for adr in branchList:
	new_row = []
	time = []
	freq = executedCount[adr]
	for key, value in sorted(freq.iteritems()):  # <time, freq>
		if x == []:
			time.append(key)
		new_row.append(value)	# freq for this <branch, time>
	z.append(list(new_row))

	if x == []:
		x = time

for i, value in enumerate(branchList):
    branchList[i] = "0x" + format(value, "x")

print "Done processing the globalheatmap data"

print "Plotting the globalheatmap data"

data = [
    go.Heatmap(
        z=z,
        x=x,
        y=branchList,
        # colorscale='Viridis',
        # colorscale=[[0, 'rgb(0,0,0)'], [1, 'rgb(255,0,0)']],
        colorscale=[[0, 'rgb(255,255,255)'], [1, 'rgb(255,0,0)']],
        hoverinfo="x+y+z"
    )
]

layout = go.Layout(
    title='Branch frequency Heatmap'+"-"+sys.argv[2],
    xaxis = dict(ticks='', nticks=15, type="linear", title="Time(ticks)"),
    yaxis = dict(ticks='' , type="category", title="Branches")
)

fig1 = go.Figure(data=data, layout=layout)
graphFile.write(plotly.offline.plot(fig1, filename="globalheatmap"+"-"+sys.argv[2]+".html",  auto_open=False, output_type='div')) 
print "Done plotting the globalheatmap data"



print "Plotting the Branch Total frequency"
t1 = []
t2 = []
t3 = []

for key in sorted(frequency.iterkeys()):
	t1.append(frequency[key])
	t2.append(takenCount[key])
	t3.append(nottakenCount[key])

trace1 = go.Bar(
    x=branchList,
    y=t1,
    name='Total'
)
trace2 = go.Bar(
    x=branchList,
    y=t2,
    name='Taken'
)
trace3 = go.Bar(
    x=branchList,
    y=t3,
    name='NotTaken'
)

data = [trace1, trace3, trace2]
layout = go.Layout(
    title='Branch execution/taken/nottakenCount'+"-"+sys.argv[2],
    barmode='group',
    yaxis = dict(ticks='', type="log", title="Count"),
    xaxis = dict(ticks='' , type="category", title="Branches")
)

fig2 = go.Figure(data=data, layout=layout)

graphFile.write(plotly.offline.plot(fig2, filename="globalheatmap"+"-"+sys.argv[2]+".html",  auto_open=False, output_type='div')) 

print "Done plotting the Branch Total frequency"



print "Plotting the Branch T/NT Phase data"
for i, key in enumerate(sorted(TNTcount.iterkeys())):
	if len(TNTcount[key]) < 5:	# no need to plot cold branches
		continue
	trace1 = go.Scatter(x = range(len(TNTcount[key])), y=TNTcount[key], line=dict(shape='hv'), mode='markers')
	data = [trace1]
	percentage = takenCount[key]*100/frequency[key]
	layout = go.Layout(
	    title='T/NT Phase '+branchList[i]+"- Taken="+ format(percentage, "d") + "% NotTaken="+ format(100-percentage, "d")   +"% - "+sys.argv[2],
	    yaxis = dict(ticks='', type="linear", rangemode="tozero", fixedrange=True, range=[0, 3], title="T=2 NT=1"),
	    xaxis = dict(ticks='', nticks=6, title="Executions")
	)

	fig3 = go.Figure(data=data, layout=layout)
	graphFile.write(plotly.offline.plot(fig3, filename="globalheatmap"+"-"+sys.argv[2]+".html",  auto_open=False, output_type='div')) 

print "Done plotting the Branch T/NT Phase data"
# TNTcount

graphFile.close()