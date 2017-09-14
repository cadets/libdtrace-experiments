BEGIN
{
/*
 * CHECK: setx %r1, 0 ! 0x0
 * CHECK-NEXT: ret %r1
 */
	trace(0);
}
