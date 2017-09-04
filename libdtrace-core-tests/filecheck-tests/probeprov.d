BEGIN
{
/*
 * CHECK: ldgs %r1, 274 ! DT_VAR(274) = "probeprov"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = probeprov;
}
