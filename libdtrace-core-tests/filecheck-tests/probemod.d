BEGIN
{
/*
 * CHECK: ldgs %rd, 275 ! DT_VAR(275) = "probemod"
 * CHECK-NEXT: stgs %rd, 1280 ! DT_VAR(1280) = "x"
 * CHECK-NEXT: ret %rd
 */
	x = probemod;
}
