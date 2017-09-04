BEGIN
{
/*
 * CHECK: ldgs %r1, 275 ! DT_VAR(275) = "probemod"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = probemod;
}
