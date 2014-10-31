#!/usr/bin/perl

$destdir = $ARGV[0]; 
$cmd = sprintf("/bin/cp nwlogger.log \"%s/nwlogger-chat.log\"", $destdir); 
printf("NWLogger: nwlogger.pl: CMD: %s\n", $cmd); 
system($cmd); 

$cmd = sprintf("/usr/bin/nohup /usr/bin/gzip -9f \"%s/nwlogger-chat.log\" &", $destdir); 
printf("NWLogger: nwlogger.pl: CMD: %s\n", $cmd); 
system($cmd); 

sleep(1); 
unlink("nohup.out"); 

exit(0); 
