BEGIN
{
/*
 * CHECK: setx DT_INTEGER[0], %r1 ! 0x0
 * CHECK-NEXT: ret %r1
 */
	trace(0);
}
