BEGIN
{
/*
 * CHECK: ldgs %r1, 288 ! DT_VAR(288) = "errno"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = errno;
}
