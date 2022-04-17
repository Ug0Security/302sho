import shodan
import sys
import re

SHODAN_API_KEY = "SHODAN_API_KEY"

api = shodan.Shodan(SHODAN_API_KEY)
PAGE = sys.argv[1]
liste = []

try:
        # Search Shodan
        results = api.search('302 "Content-length" port:443 html:"<div>" -html:"Object moved"', page=PAGE)

        # Show the results
        print 'Results found: %s' % results['total']
                
        for result in results['matches']:
		#print results
		try:
			#print result['ip_str'].rstrip()
                	#print result['data'].rstrip()
     			for line in str(result['data']).split('\n'):
				if 'Content-Length' in line:
					#print line
					if int(re.search(r'\d+', line).group()) > 10000:
						print result['ip_str'].rstrip()
						print "Content Length ==> " + re.search(r'\d+', line).group()
						liste.append(int(re.search(r'\d+', line).group()))
						
		except:
			pass


except shodan.APIError, e:
        print 'Error: %s' % e


print ""
print "--------- [Analyse] ------------"
print ""
print "Liste des Content-length"
print ""
print liste
print ""

print "Liste des Content-length par ordre croissant"
print ""
liste.sort()

for i in liste:
	print i
print ""
print "--------- [Frequence] ------------"
print ""
print "Occurence :"
print ""
my_dict = {i:liste.count(i) for i in liste} 
print my_dict
print ""

print "Occurence par ordre decroissant :"
print ""
a = sorted(my_dict.items(), key=lambda x: x[1], reverse=True)   
for i in a:
	print i
print ""

print "--------- [Fin Analyse] ------------"
