rule Win_Mysig
{
strings:
	$a0 = {636F6D646C6733322E646C6C005348454C4C33322E64}
	$a1 = "USER32.dll"
condition:
	$a0 or $a1
}