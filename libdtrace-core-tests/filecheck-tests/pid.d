BEGIN
{
/*
 * CHECK: ldgs %r1, 278 ! DT_VAR(278) = "pid"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = pid;
}
