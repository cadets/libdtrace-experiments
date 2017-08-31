BEGIN
{
/*
 * CHECK: setx %rd, 0 ! 0x0
 * CHECK-NEXT: ret %rd
 */
	trace(0);
}
