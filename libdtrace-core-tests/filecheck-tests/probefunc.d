BEGIN
{
/*
 * CHECK: ldgs %r1, 276 ! DT_VAR(276) = "probefunc"
 * CHECK-NEXT: stgs 1280, %r1 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %r1
 */
	x = probefunc;
}
