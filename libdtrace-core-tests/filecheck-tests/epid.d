BEGIN
{
/*
 * CHECK: ldgs %r1, 260 ! DT_VAR(260) = "epid"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = epid;
}

