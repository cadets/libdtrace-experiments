BEGIN
{
/*
 * CHECK: ldgs %r1, 279 ! DT_VAR(279) = "tid"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = tid;
}
