BEGIN
{
/*
 * CHECK: ldgs %r1, 285 ! DT_VAR(285) = "ppid"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = ppid;
}

