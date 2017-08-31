BEGIN
{
/*
 * CHECK: ldgs %rd, 276 ! DT_VAR(276) = "probefunc"
 * CHECK-NEXT: stgs %rd, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %rd
 */
	x = probefunc;
}
