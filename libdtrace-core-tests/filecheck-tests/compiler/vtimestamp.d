BEGIN
{
/*
 * CHECK: ldgs %r1, 258 ! DT_VAR(258) = "vtimestamp"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = vtimestamp;
}

