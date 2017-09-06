BEGIN
{
/*
 * CHECK: ldgs %r1, 284 ! DT_VAR(284) = "ucaller"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = ucaller;
}

