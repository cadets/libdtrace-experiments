BEGIN
{
/*
 * CHECK: ldgs %rd, 277 ! DT_VAR(277) = "probename"
 * CHECK-NEXT: stgs %rd, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %rd
 */
	x = probename;
}
