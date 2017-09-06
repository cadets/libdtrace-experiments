BEGIN
{
/*
 * CHECK: ldgs %r1, 289 ! DT_VAR(289) = "execargs"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = execargs;
}

