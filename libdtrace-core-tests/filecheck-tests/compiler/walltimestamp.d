BEGIN
{
/*
 * CHECK: ldgs %r1, 282 ! DT_VAR(282) = "walltimestamp"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = walltimestamp;
}

