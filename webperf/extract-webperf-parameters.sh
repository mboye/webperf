cat webperf.c|egrep "\"stats\.|\"test\.|\"dns\.|\"http\."|awk -F"\"" '{print $2 }'|uniq -u|sort
