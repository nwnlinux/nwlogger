#!/usr/bin/perl -w

use strict; 
use Time::Local; 

use vars qw( $filename $starttime $endtime $line $addr); 
use vars qw( $curchar $i $linetime ); 
use vars qw( @color_stack $color ); 
use vars qw( @tag ); 

sub read_tag($$);
sub line2time($);

$filename = $ARGV[0]; 
open(INPUT, "$filename") || die("Unable to open input file: $!\n");

$starttime = 0; 
$endtime = 0; 

$line = <INPUT>; 
chomp($line); 
$starttime = line2time($line); 

# Read the last line of the file. 
while ( <INPUT> ) {
    $addr = tell(INPUT) unless eof(INPUT);
}
seek(INPUT, $addr, 0); 
$line = <INPUT>; 
chomp($line); 
$endtime = line2time($line); 

printf("<html>\n"); 
printf("<head>\n");
printf("  <meta http-equiv=\"content-type\" content=\"text/html; charset=ISO-8859-1\">\n");
printf("  <title>\n"); 
printf("NWLogger Log: %s to %s", scalar(localtime($starttime)), scalar(localtime($endtime))); 
printf("</title>\n");
printf("</head>\n");
printf("<body style=\"background-color: rgb(0, 0, 0); color: rgb(255, 255, 255);\">\n");
printf("<h1 style=\"text-align: center;\">\n"); 
printf("NWLogger Log: %s to %s\n", scalar(localtime($starttime)), scalar(localtime($endtime))); 
printf("</h1>\n");

seek(INPUT, 0, 0); 


while( $line = <INPUT> ) { 
	chomp($line); 

	$linetime = line2time($line); 
	$line = substr( $line, 28 ); 

	# Reset the color stack every line. 
	@color_stack = (); 
	push(@color_stack, "rgb(255, 255, 255)"); 		# This is the default color, and it should never be popped. 

	printf("<span style=\"color: %s;\">", $color_stack[ scalar(@color_stack) - 1] ); 
	printf("%s: ", scalar(localtime($linetime)));

	for($i = 0; $i<length($line); $i++) {

		$curchar = substr($line, $i, 1); 
		if( $curchar eq "<" ) { 	# tag start
			@tag = read_tag($line, $i); 
			if( $tag[0] < 0 ) {	# "</c>"
				if( scalar(@color_stack) > 1 ) { 
					pop(@color_stack); 
				}
				printf("</span><span style=\"color: %s;\">", $color_stack[ scalar(@color_stack) - 1] ); 
			} 
			if( $tag[0] > 0 ) { 	# <cRGB>
				$color=sprintf("rgb(%d, %d, %d)", $tag[2], $tag[3], $tag[4]); 
				push( @color_stack, $color); 
				printf("</span><span style=\"color: %s;\">", $color_stack[ scalar(@color_stack) - 1] ); 
			} 
			if( $tag[0] != 0 ) { 
				$i = $i + ( $tag[1] - 1 ); 
			} else { 
				printf("<"); 
			}
		} else { 
			printf("%s", $curchar); 
		}
	} 
	printf("</span><br>\n"); 
} 
			
printf("</body>\n"); 
printf("</html>\n"); 

sub read_tag($$) 
{ 
	my ($data, $start) = @_; 
	my $i; 
	my @retval; 
	my $taglen; 
	my $tag; 

	@retval = (); 
	$retval[0] = 0; 
	$taglen = 0; 

	for($i = $start; $i < length($data); $i++ ) {
		if( substr( $data, $i, 1 ) eq ">" ) { 
			$taglen++;
			last; 
		} 
		$taglen++; 
	} 
	if( $i == length($data) ) { 		# No closing tag found, abort out. 
		return(@retval); 
	} 
	$tag = substr( $data, $start, $taglen); 
	if( substr($tag, 1, 1) ne "c" && substr($tag, 1, 1) ne "/" ) { 
		return(@retval); 
	} 
	if( substr($tag, 1, 1) eq "/" && substr($tag, 2, 1) ne "c" ) { 
		return(@retval); 
	} 
	if( substr($tag, 1, 1) eq "/" && substr($tag, 2, 1) eq "c" ) { 
		$retval[0] = -1; 
		$retval[1] = $taglen; 
		return(@retval); 
	} 
	if( substr($tag, 1, 1) eq "c" ) { 
		$retval[0] = 1; 
		$retval[1] = $taglen; 
		$retval[2] = ord( substr( $tag, 2, 1 ) ); 
		$retval[3] = ord( substr( $tag, 3, 1 ) ); 
		$retval[4] = ord( substr( $tag, 4, 1 ) ); 
		return(@retval); 
	} 
	return(@retval); 
}

sub line2time($) 
{ 
	my ($line) = @_; 

	my $timestamp;  
	my @timearray; 

	$timestamp = substr($line, 0, 27); 
	@timearray = split(/:/, $timestamp); 

	return( timelocal( $timearray[5], $timearray[4], $timearray[3], $timearray[2], $timearray[1] - 1, $timearray[0] - 1900)); 
}
