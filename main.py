#!/usr/bin/python -i
from optparse import OptionParser
import os
import re
report = {}
wordscore = {}
filescore = {}
filelist = list()

def sortscore(score, reverse=False):
	sortedscore = sorted(score.items(), key=lambda score: score[1], reverse=reverse)
	returnscore = []
	for s in sortedscore:
		if s[1] > 0:
			returnscore.append(s)
	
	return returnscore

def printscore(report):
	for i in report:
		print i[0] + ':' + str(i[1])

def wholeword(word, string):
	matches = []
	regexU = r'([A-Z]|[^a-zA-Z]|\b)(' + word.lower() + r')([A-Z]|[^a-zA-Z]|\b)'
	regexL = r'([a-z]|[^a-zA-Z]|\b)(' + word.upper() + r')([a-z]|[^a-zA-Z]|\b)'
	mU = re.search(regexU, string)
	if "groups" in dir(mU):
		matches.append(mU.groups())
	mL = re.search(regexL, string)
	if "groups" in dir(mL):
		matches.append(mL.groups())
	return matches

def skipfile(filename,skippedexts):
	if not isinstance(skippedexts, list):
		return False
	for skip in skippedexts:
		if filename.endswith(skip):
			return True
	return False

def scoretext(wordlist, text):
	score = {}
	for word in wordlist:
		score[word] = len(wholeword(word,text))
	
	return score

parser = OptionParser()
parser.add_option("-f", "--file", dest="suspiciousfilename", help="specify file to scan", action="append")
parser.add_option("-w", "--wordlist", dest="wordlistfilename", help="file containing all of the words to look for")
parser.add_option("-s", "--skip", dest="skipfileextensions", help="file extensions to skip", action="append")
parser.add_option("-v", "--verbose", dest="verbose", help="print verberose information", default=False)
parser.add_option("-r", "--report", dest="printreport", default="w", help="print score")

(options, args) = parser.parse_args()

if options.wordlistfilename:
	wordlist = open(options.wordlistfilename).read().lower().split()

for a in args:
	for (path, dirs, files) in os.walk(a):
		for file in files:
			filelist.append(path + '/' + file)
	
if options.suspiciousfilename:
	filelist += options.suspiciousfilename

for file in filelist:
	if skipfile(file, options.skipfileextensions):
		#print "skip: " + file
		continue
	try:
		f = open(file)
	except:
		print "failed to open: " + file
		continue
	
	filecontents = f.read()
			
	report[file] = scoretext(wordlist, filecontents)

for file in report.keys():
	for word in report[file].keys():
		if not word in wordscore:
			wordscore[word] = 0
		if not file in filescore:
			filescore[file] = 0
		wordscore[word] += report[file][word]
		filescore[file] += report[file][word]

if options.printreport:
	if options.printreport == "f":
		printscore(sortscore(filescore))
	else:
		printscore(sortscore(wordscore))

def test():
	print wholeword("ear","bearth")
	print wholeword("ear","BearTH")
	print wholeword("ear","bEARth")
	print wholeword("ear","ear_")
	print wholeword("ear","ear()")
	print wholeword("ear","ear.")
	print wholeword("ear","ear:")
	print wholeword("ear","ear\n\r")
	print wholeword("ear","myEAR() MYear: myEAR()")

#test()
