BEGIN
{
/*
 * CHECK: ldgs %r1, 256 ! DT_VAR(256) = "curthread"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = curthread;
}