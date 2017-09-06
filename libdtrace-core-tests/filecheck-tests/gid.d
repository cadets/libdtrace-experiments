BEGIN
{
/*
 * CHECK: ldgs %r1, 287 ! DT_VAR(287) = "gid"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = gid;
}

