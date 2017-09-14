BEGIN
{
/*
 * CHECK: ldgs %r1, 277 ! DT_VAR(277) = "probename"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = probename;
}
