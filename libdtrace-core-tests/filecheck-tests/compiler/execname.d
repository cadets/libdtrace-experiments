BEGIN
{
/*
 * CHECK: ldgs %r1, 280 ! DT_VAR(280) = "execname"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = execname;
}

