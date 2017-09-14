BEGIN
{
/*
 * CHECK: ldgs %r1, 272 ! DT_VAR(272) = "stackdepth"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = stackdepth;
}

