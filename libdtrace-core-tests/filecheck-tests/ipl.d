BEGIN
{
/*
 * CHECK: ldgs %r1, 259 ! DT_VAR(259) = "ipl"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = ipl;
}

