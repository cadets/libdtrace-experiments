BEGIN
{
/*
 * CHECK: ldgs %r1, 283 ! DT_VAR(283) = "ustackdepth"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = ustackdepth;
}

