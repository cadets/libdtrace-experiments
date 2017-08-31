BEGIN
{
/*
 * CHECK: ldgs %rd, 274 ! DT_VAR(274) = "probeprov"
 * CHECK-NEXT: stgs %rd, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %rd
 */
	x = probeprov;
}
